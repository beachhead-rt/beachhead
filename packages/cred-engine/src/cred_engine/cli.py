"""CLI entry point for the credential scanning engine.

Provides commands for scanning local directories, querying the findings
database, and exporting results. Designed for easy extension into a
TUI with rich tables and progress display.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="cred-engine",
    help="Portable credential scanning engine with confidence scoring.",
    no_args_is_help=True,
)
console = Console(stderr=True)

_DEFAULT_DB = Path("findings.sqlite")

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _check_fail_on(findings: list, fail_on: str | None) -> None:
    """Exit with code 2 if any finding meets or exceeds the *fail_on* severity."""
    if not fail_on or not findings:
        return
    threshold = _SEVERITY_RANK.get(fail_on.lower(), -1)
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if _SEVERITY_RANK.get(sev, 0) >= threshold:
            raise typer.Exit(2)


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Directory to scan for credentials")],
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    repo_name: Annotated[str, typer.Option("--repo", "-r", help="Repository name override")] = "",
    verify: Annotated[bool, typer.Option("--verify", help="Attempt live verification of found credentials")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    allowlist_path: Annotated[
        Path | None, typer.Option("--allowlist", help="Path to allowlist JSON file")
    ] = None,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database for later retrieval")
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit 2 if any finding at or above this severity"),
    ] = None,
) -> None:
    """Scan a local directory for committed credentials."""
    from cred_engine.allowlist import load_allowlist
    from cred_engine.patterns import PATTERNS
    from cred_engine.pipeline import process_hit
    from cred_engine.search import search_local
    from cred_engine.store import FindingsStore

    if not target.is_dir():
        console.print(f"[red]Not a directory: {target}[/red]")
        raise typer.Exit(1)

    allowlist_entries = load_allowlist(allowlist_path)
    name = repo_name or target.name

    with FindingsStore(db) as store:
        run_id = store.start_run(
            org="local",
            repos_scanned=1,
            patterns_used=len(PATTERNS),
            tool="cred-scan",
        )

        findings = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(PATTERNS))

            for pattern in PATTERNS:
                progress.update(task, description=f"[cyan]{pattern.name}[/cyan]")
                hits = search_local(target, pattern, repo_name=name)

                for hit in hits:
                    finding = process_hit(
                        repo=hit.repo,
                        file_path=hit.file_path,
                        branch=hit.branch,
                        content=hit.content,
                        url=hit.url,
                        project=hit.project,
                        pattern=pattern,
                        store=store,
                        run_id=run_id,
                        verify=verify,
                        allowlist_entries=allowlist_entries,
                        store_secrets=store_secrets,
                    )
                    if finding:
                        findings.append(finding)

                progress.advance(task)

        new_count = len(findings)
        store.finish_run(run_id, total_findings=new_count, new_findings=new_count, deduped_findings=0)

    if json_output:
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2))
        sys.stdout.write("\n")
    else:
        _print_scan_summary(findings)
    _check_fail_on(findings, fail_on)


@app.command()
def query(
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    severity: Annotated[str, typer.Option("--severity", "-s", help="Filter by severity")] = "",
    confidence: Annotated[str, typer.Option("--confidence", "-c", help="Filter by confidence")] = "",
    triage: Annotated[str, typer.Option("--triage", "-t", help="Filter by triage status")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max results")] = 50,
) -> None:
    """Query findings from the database."""
    from cred_engine.store import FindingsStore

    if not db.exists():
        console.print(f"[red]Database not found: {db}[/red]")
        raise typer.Exit(1)

    with FindingsStore(db) as store:
        results = store.query_findings(
            severity=severity,
            confidence=confidence,
            triage_status=triage,
            limit=limit,
        )

    if json_output:
        sys.stdout.write(json.dumps(results, indent=2))
        sys.stdout.write("\n")
    else:
        _print_findings_table(results)


@app.command()
def summary(
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
) -> None:
    """Show summary statistics from the findings database."""
    from cred_engine.store import FindingsStore

    if not db.exists():
        console.print(f"[red]Database not found: {db}[/red]")
        raise typer.Exit(1)

    with FindingsStore(db) as store:
        stats = store.summary()

    if json_output:
        sys.stdout.write(json.dumps(stats, indent=2))
        sys.stdout.write("\n")
    else:
        _print_summary(stats)


@app.command()
def triage(
    finding_id: Annotated[str, typer.Argument(help="Finding ID to triage")],
    status: Annotated[str, typer.Argument(help="Triage status: open, confirmed, fp, ignored")],
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    by: Annotated[str, typer.Option("--by", help="Who triaged this")] = "",
    reason: Annotated[str, typer.Option("--reason", help="Reason for triage")] = "",
) -> None:
    """Set the triage status of a finding."""
    from cred_engine.store import FindingsStore

    with FindingsStore(db) as store:
        ok = store.triage(finding_id, status, by=by, reason=reason)

    if ok:
        console.print(f"[green]Finding {finding_id} triaged as {status}[/green]")
    else:
        console.print(f"[red]Finding {finding_id} not found[/red]")
        raise typer.Exit(1)


@app.command()
def reveal(
    finding_id: Annotated[str, typer.Argument(help="Finding ID to reveal the credential for")],
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
) -> None:
    """Reveal the stored raw credential value for a finding.

    Only works for findings scanned with --store-secrets. The database
    file should be treated as sensitive when secrets are stored.
    """
    from cred_engine.store import FindingsStore

    if not db.exists():
        console.print(f"[red]Database not found: {db}[/red]")
        raise typer.Exit(1)

    with FindingsStore(db) as store:
        finding = store.get_finding(finding_id)
        if not finding:
            console.print(f"[red]Finding {finding_id} not found[/red]")
            raise typer.Exit(1)

        secret = store.get_secret(finding_id)

    evidence = json.loads(finding["evidence"]) if isinstance(finding["evidence"], str) else finding["evidence"]
    metadata = json.loads(finding["metadata"]) if isinstance(finding["metadata"], str) else finding["metadata"]

    credential_type = evidence.get("credential_type") or evidence.get("pattern", "")
    variable_name = evidence.get("variable_name", "")
    file_path = evidence.get("file_path", "")
    repo = evidence.get("repo", "")
    branch = evidence.get("branch", "")
    source = metadata.get("source", {})

    if json_output:
        out: dict[str, Any] = {
            "id": finding["id"],
            "credential_type": credential_type,
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "confidence_score": finding["confidence_score"],
        }
        if variable_name:
            out["variable_name"] = variable_name
        if file_path:
            out["file_path"] = file_path
        if repo:
            out["repo"] = repo
        if branch:
            out["branch"] = branch
        out["resource"] = finding["resource"]
        out["project"] = finding["project"]
        if finding["url"]:
            out["url"] = finding["url"]
        if source:
            out["source"] = source
        out["triage_status"] = finding["triage_status"]
        out["secret_stored"] = secret is not None
        out["secret_value"] = secret
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
    else:
        console.print(f"[bold]Finding:[/bold]    {finding['id']}")
        console.print(f"[bold]Type:[/bold]       {credential_type}")
        console.print(f"[bold]Severity:[/bold]   {finding['severity']}")
        console.print(f"[bold]Confidence:[/bold] {finding['confidence']} ({finding['confidence_score']})")
        if variable_name:
            console.print(f"[bold]Variable:[/bold]   {variable_name}")
        if file_path:
            console.print(f"[bold]File:[/bold]       {file_path}")
        if repo:
            console.print(f"[bold]Repo:[/bold]       {repo}")
        if branch:
            console.print(f"[bold]Branch:[/bold]     {branch}")
        console.print(f"[bold]Resource:[/bold]   {finding['resource']}")
        if finding["project"]:
            console.print(f"[bold]Project:[/bold]    {finding['project']}")
        if finding["url"]:
            console.print(f"[bold]URL:[/bold]        {finding['url']}")
        if source:
            console.print(f"[bold]Source:[/bold]     {source.get('type', '')}: {source.get('name', '')}")
        console.print(f"[bold]Triage:[/bold]     {finding['triage_status']}")
        if secret:
            console.print(f"\n[bold yellow]Credential value:[/bold yellow] {secret}")
        else:
            console.print(
                "\n[dim]No credential value stored. "
                "Re-scan with --store-secrets to persist raw values.[/dim]"
            )


@app.command()
def clusters(
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    min_repos: Annotated[int, typer.Option("--min-repos", help="Minimum repos for a cluster")] = 2,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
) -> None:
    """Show credential reuse clusters (same secret in multiple repos)."""
    from cred_engine.store import FindingsStore

    if not db.exists():
        console.print(f"[red]Database not found: {db}[/red]")
        raise typer.Exit(1)

    with FindingsStore(db) as store:
        result = store.find_reuse_clusters(min_repos=min_repos)

    if json_output:
        sys.stdout.write(json.dumps(result, indent=2))
        sys.stdout.write("\n")
    else:
        if not result:
            console.print("[dim]No credential reuse clusters found.[/dim]")
            return
        table = Table(title="Credential Reuse Clusters")
        table.add_column("Secret Hash", style="dim", max_width=12)
        table.add_column("Repos", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Patterns")
        table.add_column("Confirmed", justify="center")
        for c in result:
            table.add_row(
                c["secret_hash"][:12] + "...",
                str(c["repo_count"]),
                str(c["finding_count"]),
                ", ".join(c["patterns"][:3]),
                "Y" if c["has_confirmed"] else "",
            )
        console.print(table)


@app.command()
def export(
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
) -> None:
    """Export all findings as JSON."""
    from cred_engine.store import FindingsStore

    with FindingsStore(db) as store:
        data = store.export_json()

    text = json.dumps(data, indent=2) + "\n"
    if output:
        output.write_text(text)
        console.print(f"[green]Exported {len(data)} findings to {output}[/green]")
    else:
        sys.stdout.write(text)


@app.command("check-var")
def check_var(
    name: Annotated[str, typer.Argument(help="Variable name")],
    value: Annotated[str, typer.Option("--value", "-v", help="Credential value (or use --env)")] = "",
    env: Annotated[str, typer.Option("--env", "-e", help="Read value from this env var")] = "",
    resource: Annotated[str, typer.Option("--resource", "-r", help="Source resource name")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
) -> None:
    """Classify and score a single credential variable."""
    import os

    from cred_engine.var_classifier import classify
    from cred_engine.var_confidence import score_target
    from cred_engine.var_models import CredentialTarget

    actual_value = value or os.environ.get(env, "")
    if not actual_value:
        console.print("[red]Provide --value or --env with a valid environment variable[/red]")
        raise typer.Exit(1)

    cred_type = classify(actual_value, name)
    target = CredentialTarget(
        check_id=f"CRED-{cred_type.value.upper()}",
        variable_name=name,
        resource=resource,
        value=actual_value,
        credential_type=cred_type,
    )
    conf_score, conf_label, signals = score_target(target)

    if json_output:
        sys.stdout.write(json.dumps({
            "variable_name": name,
            "credential_type": cred_type.value,
            "confidence_score": conf_score,
            "confidence_label": conf_label,
            "redacted_value": target.redacted_value,
            "signals": signals,
        }, indent=2) + "\n")
    else:
        sev_style = _CONFIDENCE_STYLE.get(conf_label, "")
        console.print(f"[bold]Variable:[/bold]  {name}")
        console.print(f"[bold]Type:[/bold]      {cred_type.value}")
        console.print(f"[bold]Confidence:[/bold] [{sev_style}]{conf_label} ({conf_score:.0f})[/]")
        console.print(f"[bold]Redacted:[/bold]   {target.redacted_value}")
        if signals:
            console.print("\n[bold]Scoring signals:[/bold]")
            for s in signals:
                sign = "+" if s["score"] >= 0 else ""
                console.print(f"  {sign}{s['score']:.0f}  {s['reason']}")


@app.command("scan-ado")
def scan_ado(
    org: Annotated[str, typer.Argument(help="Azure DevOps organization name")],
    pat: Annotated[str, typer.Option("--pat", envvar="ADO_PAT", help="Personal access token")] = "",
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    projects: Annotated[
        list[str] | None, typer.Option("--project", "-p", help="Specific project(s) to scan")
    ] = None,
    no_builds: Annotated[bool, typer.Option("--no-builds", help="Skip YAML/build pipeline definitions")] = False,
    no_groups: Annotated[bool, typer.Option("--no-groups", help="Skip variable groups")] = False,
    no_releases: Annotated[bool, typer.Option("--no-releases", help="Skip classic release definitions")] = False,
    min_confidence: Annotated[float, typer.Option("--min-confidence", help="Minimum score to include")] = 0.0,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database for later retrieval")
    ] = False,
) -> None:
    """Scan an Azure DevOps organization for credentials in pipeline variables.

    Fetches variables from YAML/build pipelines, variable groups, and classic
    release pipelines. Classifies, scores, and persists findings.

    \b
    Requires an ADO PAT with Build (Read) and Variable Groups (Read) permissions.
    Classic release scanning also requires Release (Read) scope.
    """
    from cred_engine.ado_loader import AdoVariableLoader
    from cred_engine.store import FindingsStore
    from cred_engine.var_pipeline import scan_variables

    if not pat:
        console.print("[red]PAT required — set ADO_PAT or use --pat[/red]")
        raise typer.Exit(1)

    with AdoVariableLoader(org, pat) as loader:
        console.print(f"[bold]Scanning ADO org:[/bold] {org}")
        ado_result = loader.scan_org(
            projects=projects or None,
            include_builds=not no_builds,
            include_groups=not no_groups,
            include_releases=not no_releases,
        )

    console.print(
        f"  Projects: {ado_result.projects_scanned}  "
        f"Build pipelines: {ado_result.pipelines_scanned}  "
        f"Variable groups: {ado_result.groups_scanned}  "
        f"Release definitions: {ado_result.release_definitions_scanned}  "
        f"Variables found: {len(ado_result.variables)}"
    )

    if not ado_result.variables:
        console.print("[dim]No variables found to scan.[/dim]")
        return

    var_dicts = ado_result.to_var_dicts()

    with FindingsStore(db) as store:
        run_id = store.start_run(
            org=org,
            repos_scanned=ado_result.pipelines_scanned + ado_result.release_definitions_scanned,
            patterns_used=0,
            tool="cred-check",
        )
        targets = scan_variables(
            var_dicts,
            store=store,
            run_id=run_id,
            min_confidence=min_confidence,
            store_secrets=store_secrets,
        )
        store.finish_run(run_id, total_findings=len(targets), new_findings=len(targets))

    if json_output:
        sys.stdout.write(json.dumps([{
            "variable_name": t.variable_name,
            "credential_type": t.credential_type.value,
            "confidence_score": t.confidence_score,
            "confidence_label": t.confidence_label,
            "redacted_value": t.redacted_value,
            "resource": t.resource,
            "project": t.project,
        } for t in targets], indent=2) + "\n")
    else:
        if not targets:
            console.print("[green]No credentials found above threshold.[/green]")
            return
        table = Table(title=f"ADO Variable Scan ({len(targets)} findings)")
        table.add_column("Type", max_width=25)
        table.add_column("Confidence", width=12)
        table.add_column("Variable", max_width=30)
        table.add_column("Source", max_width=40)
        for t in sorted(targets, key=lambda x: x.confidence_score, reverse=True):
            style = _CONFIDENCE_STYLE.get(t.confidence_label, "")
            source = t.resource
            if t.source_pipeline:
                source = f"[pipeline] {source}"
            elif t.source_group:
                source = f"[group] {source}"
            table.add_row(
                t.credential_type.value,
                f"[{style}]{t.confidence_label} ({t.confidence_score:.0f})[/]",
                t.variable_name,
                source,
            )
        console.print(table)


@app.command("scan-ado-code")
def scan_ado_code(
    org: Annotated[str, typer.Argument(help="Azure DevOps organization name")],
    pat: Annotated[str, typer.Option("--pat", envvar="ADO_PAT", help="Personal access token")] = "",
    project: Annotated[str | None, typer.Option("--project", "-p", help="Specific project to scan")] = None,
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database")
    ] = False,
    verify: Annotated[bool, typer.Option("--verify", help="Attempt live verification of found credentials")] = False,
    allowlist_path: Annotated[
        Path | None, typer.Option("--allowlist", help="Path to allowlist JSON file")
    ] = None,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 2 if any finding at or above this severity")
    ] = None,
) -> None:
    """Scan ADO repos via Code Search API for credentials.

    \b
    Searches each credential pattern against the ADO Code Search API and
    processes hits through the scoring and entropy pipeline.
    Requires a PAT with Code (Read) scope.
    """
    from cred_engine.ado_client import AdoClient
    from cred_engine.ado_code_search import search_ado_code
    from cred_engine.allowlist import load_allowlist
    from cred_engine.patterns import PATTERNS
    from cred_engine.pipeline import process_hit
    from cred_engine.store import FindingsStore

    if not pat:
        console.print("[red]PAT required — set ADO_PAT or use --pat[/red]")
        raise typer.Exit(1)

    allowlist_entries = load_allowlist(allowlist_path)

    with AdoClient(org, pat) as client, FindingsStore(db) as store:
        run_id = store.start_run(
            org=org,
            patterns_used=len(PATTERNS),
            tool="cred-scan",
        )

        findings = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning ADO code...", total=len(PATTERNS))

            for pattern in PATTERNS:
                progress.update(task, description=f"[cyan]{pattern.name}[/cyan]")
                hits = search_ado_code(client, pattern, project=project)

                for hit in hits:
                    finding = process_hit(
                        repo=hit.repo,
                        file_path=hit.file_path,
                        branch=hit.branch,
                        content=hit.content,
                        url=hit.url,
                        project=hit.project,
                        pattern=pattern,
                        store=store,
                        run_id=run_id,
                        verify=verify,
                        allowlist_entries=allowlist_entries,
                        store_secrets=store_secrets,
                    )
                    if finding:
                        findings.append(finding)

                progress.advance(task)

        new_count = len(findings)
        store.finish_run(run_id, total_findings=new_count, new_findings=new_count)

    if json_output:
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2))
        sys.stdout.write("\n")
    else:
        _print_scan_summary(findings)
    _check_fail_on(findings, fail_on)


@app.command("scan-ado-logs")
def scan_ado_logs(
    org: Annotated[str, typer.Argument(help="Azure DevOps organization name")],
    pat: Annotated[str, typer.Option("--pat", envvar="ADO_PAT", help="Personal access token")] = "",
    project: Annotated[str | None, typer.Option("--project", "-p", help="Specific project to scan")] = None,
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database")
    ] = False,
    top: Annotated[int, typer.Option("--top", help="Number of recent builds to scan")] = 20,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 2 if any finding at or above this severity")
    ] = None,
) -> None:
    """Scan pipeline build logs for leaked credentials.

    \b
    Fetches recent build logs and scans them for credential patterns.
    Requires a PAT with Build (Read) scope.
    """
    from cred_engine.ado_client import AdoClient
    from cred_engine.ado_log_scanner import persist_hits, scan_pipeline_logs
    from cred_engine.store import FindingsStore

    if not pat:
        console.print("[red]PAT required — set ADO_PAT or use --pat[/red]")
        raise typer.Exit(1)

    with AdoClient(org, pat) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Scanning pipeline logs...", total=None)
            hits = scan_pipeline_logs(client, project=project, top=top)
        console.print(f"  Found {len(hits)} credential(s) in pipeline logs")

        with FindingsStore(db) as store:
            run_id = store.start_run(org=org, tool="cred-scan")
            findings, new_count, dedup_count = persist_hits(
                hits, store, run_id, store_secrets=store_secrets,
            )
            store.finish_run(run_id, total_findings=len(findings), new_findings=new_count, deduped_findings=dedup_count)

    if json_output:
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2))
        sys.stdout.write("\n")
    else:
        _print_ado_surface_table(findings, "Pipeline Log Scan")
    _check_fail_on(findings, fail_on)


@app.command("scan-ado-prs")
def scan_ado_prs(
    org: Annotated[str, typer.Argument(help="Azure DevOps organization name")],
    pat: Annotated[str, typer.Option("--pat", envvar="ADO_PAT", help="Personal access token")] = "",
    project: Annotated[str | None, typer.Option("--project", "-p", help="Specific project to scan")] = None,
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database")
    ] = False,
    status: Annotated[
        str, typer.Option("--status", help="PR status filter: all, active, completed, abandoned")
    ] = "all",
    top: Annotated[int, typer.Option("--top", help="Number of PRs to scan")] = 100,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 2 if any finding at or above this severity")
    ] = None,
) -> None:
    """Scan PR comments for credentials.

    \b
    Fetches pull request comments and scans them for credential patterns.
    Requires a PAT with Code (Read) scope.
    """
    from cred_engine.ado_client import AdoClient
    from cred_engine.ado_pr_scanner import persist_hits, scan_pull_requests
    from cred_engine.store import FindingsStore

    if not pat:
        console.print("[red]PAT required — set ADO_PAT or use --pat[/red]")
        raise typer.Exit(1)

    with AdoClient(org, pat) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Scanning pull requests...", total=None)
            hits = scan_pull_requests(client, project=project, status=status, top=top)
        console.print(f"  Found {len(hits)} credential(s) in PR comments")

        with FindingsStore(db) as store:
            run_id = store.start_run(org=org, tool="cred-scan")
            findings, new_count, dedup_count = persist_hits(
                hits, store, run_id, store_secrets=store_secrets,
            )
            store.finish_run(run_id, total_findings=len(findings), new_findings=new_count, deduped_findings=dedup_count)

    if json_output:
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2))
        sys.stdout.write("\n")
    else:
        _print_ado_surface_table(findings, "PR Comment Scan")
    _check_fail_on(findings, fail_on)


@app.command("scan-ado-workitems")
def scan_ado_workitems(
    org: Annotated[str, typer.Argument(help="Azure DevOps organization name")],
    pat: Annotated[str, typer.Option("--pat", envvar="ADO_PAT", help="Personal access token")] = "",
    project: Annotated[str | None, typer.Option("--project", "-p", help="Specific project to scan")] = None,
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database")
    ] = False,
    top: Annotated[int, typer.Option("--top", help="Number of work items to scan")] = 1000,
    no_comments: Annotated[bool, typer.Option("--no-comments", help="Skip scanning work item comments")] = False,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 2 if any finding at or above this severity")
    ] = None,
) -> None:
    """Scan work item fields and comments for credentials.

    \b
    Queries work items and scans their fields and comments for credential
    patterns. Requires a PAT with Work Items (Read) scope.
    """
    from cred_engine.ado_client import AdoClient
    from cred_engine.ado_workitem_scanner import persist_hits, scan_workitems
    from cred_engine.store import FindingsStore

    if not pat:
        console.print("[red]PAT required — set ADO_PAT or use --pat[/red]")
        raise typer.Exit(1)

    with AdoClient(org, pat) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Scanning work items...", total=None)
            hits = scan_workitems(client, project=project, top=top, scan_comments=not no_comments)
        console.print(f"  Found {len(hits)} credential(s) in work items")

        with FindingsStore(db) as store:
            run_id = store.start_run(org=org, tool="cred-scan")
            findings, new_count, dedup_count = persist_hits(
                hits, store, run_id, store_secrets=store_secrets,
            )
            store.finish_run(run_id, total_findings=len(findings), new_findings=new_count, deduped_findings=dedup_count)

    if json_output:
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2))
        sys.stdout.write("\n")
    else:
        _print_ado_surface_table(findings, "Work Item Scan")
    _check_fail_on(findings, fail_on)


@app.command("scan-ado-wikis")
def scan_ado_wikis(
    org: Annotated[str, typer.Argument(help="Azure DevOps organization name")],
    pat: Annotated[str, typer.Option("--pat", envvar="ADO_PAT", help="Personal access token")] = "",
    project: Annotated[str | None, typer.Option("--project", "-p", help="Specific project to scan")] = None,
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database")
    ] = False,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 2 if any finding at or above this severity")
    ] = None,
) -> None:
    """Scan wiki pages for credentials.

    \b
    Fetches wiki pages and scans their content for credential patterns.
    Requires a PAT with Wiki (Read) scope.
    """
    from cred_engine.ado_client import AdoClient
    from cred_engine.ado_wiki_scanner import persist_hits, scan_wikis
    from cred_engine.store import FindingsStore

    if not pat:
        console.print("[red]PAT required — set ADO_PAT or use --pat[/red]")
        raise typer.Exit(1)

    with AdoClient(org, pat) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Scanning wikis...", total=None)
            hits = scan_wikis(client, project=project)
        console.print(f"  Found {len(hits)} credential(s) in wiki pages")

        with FindingsStore(db) as store:
            run_id = store.start_run(org=org, tool="cred-scan")
            findings, new_count, dedup_count = persist_hits(
                hits, store, run_id, store_secrets=store_secrets,
            )
            store.finish_run(run_id, total_findings=len(findings), new_findings=new_count, deduped_findings=dedup_count)

    if json_output:
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2))
        sys.stdout.write("\n")
    else:
        _print_ado_surface_table(findings, "Wiki Scan")
    _check_fail_on(findings, fail_on)


@app.command("scan-vars")
def scan_vars(
    input_file: Annotated[Path, typer.Argument(help="JSON file with variable list [{name, value, ...}]")],
    db: Annotated[Path, typer.Option("--db", "-d", help="SQLite database path")] = _DEFAULT_DB,
    resource: Annotated[str, typer.Option("--resource", "-r", help="Default resource name")] = "",
    project: Annotated[str, typer.Option("--project", "-p", help="Default project name")] = "",
    min_confidence: Annotated[float, typer.Option("--min-confidence", help="Minimum score to include")] = 0.0,
    json_output: Annotated[bool, typer.Option("--json", help="Output JSON to stdout")] = False,
    store_secrets: Annotated[
        bool, typer.Option("--store-secrets", help="Store raw credential values in the database for later retrieval")
    ] = False,
) -> None:
    """Scan a JSON file of pipeline variables for credentials.

    Input format: a JSON array of objects with at least 'name' and 'value' keys.
    Optional keys: 'resource', 'project', 'source_pipeline', 'source_group'.
    """
    from cred_engine.store import FindingsStore
    from cred_engine.var_pipeline import scan_variables

    if not input_file.exists():
        console.print(f"[red]File not found: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        variables = json.loads(input_file.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        console.print(f"[red]Failed to parse {input_file}: {exc}[/red]")
        raise typer.Exit(1) from None
    if not isinstance(variables, list):
        console.print("[red]Input must be a JSON array[/red]")
        raise typer.Exit(1)

    with FindingsStore(db) as store:
        run_id = store.start_run(
            org="variable-scan",
            patterns_used=0,
            tool="cred-check",
        )
        targets = scan_variables(
            variables,
            resource=resource,
            project=project,
            store=store,
            run_id=run_id,
            min_confidence=min_confidence,
            store_secrets=store_secrets,
        )
        store.finish_run(run_id, total_findings=len(targets), new_findings=len(targets))

    if json_output:
        sys.stdout.write(json.dumps([{
            "variable_name": t.variable_name,
            "credential_type": t.credential_type.value,
            "confidence_score": t.confidence_score,
            "confidence_label": t.confidence_label,
            "redacted_value": t.redacted_value,
            "resource": t.resource,
        } for t in targets], indent=2) + "\n")
    else:
        if not targets:
            console.print("[green]No credentials found above threshold.[/green]")
            return
        table = Table(title=f"Variable Scan ({len(targets)} findings)")
        table.add_column("Type", max_width=25)
        table.add_column("Confidence", width=12)
        table.add_column("Variable", max_width=30)
        table.add_column("Resource", max_width=30)
        for t in sorted(targets, key=lambda x: x.confidence_score, reverse=True):
            style = _CONFIDENCE_STYLE.get(t.confidence_label, "")
            table.add_row(
                t.credential_type.value,
                f"[{style}]{t.confidence_label} ({t.confidence_score:.0f})[/]",
                t.variable_name,
                t.resource,
            )
        console.print(table)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_CONFIDENCE_STYLE = {
    "confirmed": "bold green",
    "high": "green",
    "medium": "yellow",
    "low": "dim yellow",
    "likely-fp": "dim",
}


def _print_scan_summary(findings: list) -> None:
    if not findings:
        console.print("[green]No credentials found.[/green]")
        return

    table = Table(title=f"Scan Results ({len(findings)} findings)")
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=12)
    table.add_column("Pattern", max_width=30)
    table.add_column("File", max_width=50)

    for f in findings:
        sev = f.severity.value
        conf = f.metadata.get("confidence", "medium")
        table.add_row(
            f"[{_SEVERITY_STYLE.get(sev, '')}]{sev}[/]",
            f"[{_CONFIDENCE_STYLE.get(conf, '')}]{conf}[/]",
            f.evidence.get("pattern", f.check_id),
            f.evidence.get("file_path", f.resource),
        )
    console.print(table)


def _print_ado_surface_table(findings: list, title: str) -> None:
    """Rich table for ADO surface scanner results (logs, PRs, work items, wikis)."""
    if not findings:
        console.print("[green]No credentials found.[/green]")
        return

    table = Table(title=f"{title} ({len(findings)} findings)")
    table.add_column("Severity", width=10)
    table.add_column("Check", max_width=25)
    table.add_column("Title", max_width=45)
    table.add_column("Project", max_width=20)

    for f in findings:
        sev = f.severity.value
        table.add_row(
            f"[{_SEVERITY_STYLE.get(sev, '')}]{sev}[/]",
            f.check_id,
            f.title[:45],
            f.project,
        )
    console.print(table)


def _print_findings_table(results: list[dict]) -> None:
    if not results:
        console.print("[dim]No findings match the filters.[/dim]")
        return

    table = Table(title=f"Findings ({len(results)})")
    table.add_column("ID", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=12)
    table.add_column("Triage", width=10)
    table.add_column("Title", max_width=60)

    for r in results:
        sev = r["severity"]
        conf = r["confidence"]
        table.add_row(
            r["id"],
            f"[{_SEVERITY_STYLE.get(sev, '')}]{sev}[/]",
            f"[{_CONFIDENCE_STYLE.get(conf, '')}]{conf}[/]",
            r["triage_status"],
            r["title"][:60],
        )
    console.print(table)


def _print_summary(stats: dict) -> None:
    console.print(f"\n[bold]Total findings:[/bold] {stats['total']}")

    if stats.get("by_severity"):
        console.print("\n[bold]By severity:[/bold]")
        for sev, count in sorted(stats["by_severity"].items()):
            style = _SEVERITY_STYLE.get(sev, "")
            console.print(f"  [{style}]{sev:>10}[/]: {count}")

    if stats.get("by_confidence"):
        console.print("\n[bold]By confidence:[/bold]")
        for conf, count in sorted(stats["by_confidence"].items()):
            style = _CONFIDENCE_STYLE.get(conf, "")
            console.print(f"  [{style}]{conf:>10}[/]: {count}")

    if stats.get("by_triage"):
        console.print("\n[bold]By triage:[/bold]")
        for status, count in sorted(stats["by_triage"].items()):
            console.print(f"  {status:>10}: {count}")
