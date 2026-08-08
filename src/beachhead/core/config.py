"""Engagement scope config loading (core/config.py).

Loads the untracked engagement.local.yaml (see docs/opsec-and-scope.md) into an immutable
EngagementConfig and computes a scope_hash over the authorized boundary. The hash is recorded
on the store's engagement row so a boundary change is detectable. No secrets live here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml

from beachhead.core.errors import ConfigError, ConfigMissingError

__all__ = ["EngagementConfig", "load_config", "resolve_config_path", "bootstrap_config"]

_DEFAULT_CONFIG_NAME = "engagement.local.yaml"
_ENV_VAR = "BEACHHEAD_ENGAGEMENT"
_DEFAULT_WINDOW_DAYS = 90
_UNSAFE_PATH = re.compile(r"[/\\?#%\x00-\x1f]")


@dataclass(frozen=True)
class EngagementConfig:
    """Immutable engagement boundary. Satisfies module.EngagementConfig structurally.

    No ``slots=True`` so ``scope_hash`` can memoize via ``cached_property``.
    """

    engagement: str
    authorization_ref: str
    window_start: datetime
    window_end: datetime
    tenants: frozenset[str]
    management_groups: frozenset[str]
    subscriptions: frozenset[str]
    resource_scopes: tuple[str, ...]
    ado_organizations: frozenset[str]
    allow_write: bool
    window_explicit: bool = False

    @cached_property
    def scope_hash(self) -> str:
        """SHA-256 over the authorized-boundary fields only (cosmetic labels excluded).

        Auto-generated windows (no explicit ``window:`` in config) are excluded — they
        change every load since they're anchored to ``now()``, which would cause a
        spurious mismatch on every CLI/TUI invocation.
        """
        payload: dict[str, object] = {
            "tenants": sorted(self.tenants),
            "management_groups": sorted(self.management_groups),
            "subscriptions": sorted(self.subscriptions),
            "resource_scopes": sorted(self.resource_scopes),
            "ado_organizations": sorted(self.ado_organizations),
            "allow_write": self.allow_write,
        }
        if self.window_explicit:
            payload["window_start"] = self.window_start.isoformat()
            payload["window_end"] = self.window_end.isoformat()
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


def load_config(path: str | Path | None = None) -> EngagementConfig:
    """Load + validate the engagement config. Raises ConfigError on any problem."""
    resolved = _resolve_path(path)
    if not resolved.is_file():
        raise ConfigMissingError(str(resolved))
    try:
        raw = yaml.safe_load(resolved.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError(f"engagement config is not valid YAML: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigError("engagement config must be a YAML mapping")
    return _build(raw)


def resolve_config_path(path: str | Path | None = None) -> Path:
    """Return the config file path that load_config would use."""
    if path is not None:
        return Path(path)
    env = os.environ.get(_ENV_VAR)
    if env:
        return Path(env)
    return Path(_DEFAULT_CONFIG_NAME)


_resolve_path = resolve_config_path


def _build(raw: Mapping[str, Any]) -> EngagementConfig:
    window = raw.get("window")
    window_explicit = False
    if isinstance(window, Mapping):
        window_start = _parse_dt(window.get("start"), "window.start")
        window_end = _parse_dt(window.get("end"), "window.end")
        if window_end <= window_start:
            raise ConfigError("window.end must be after window.start")
        window_explicit = True
    elif window is None:
        now = datetime.now(tz=UTC)
        window_start = now
        window_end = now + timedelta(days=_DEFAULT_WINDOW_DAYS)
    else:
        raise ConfigError("window must be a mapping with start/end (or omit for 90-day default)")

    tenants = _str_set(raw.get("tenants"), "tenants")
    management_groups = _str_set(raw.get("management_groups"), "management_groups")
    subscriptions = _str_set(raw.get("subscriptions"), "subscriptions")
    resource_scopes = _str_tuple(raw.get("resource_scopes"), "resource_scopes")
    ado_organizations = _str_set(raw.get("ado_organizations"), "ado_organizations")

    for org_name in ado_organizations:
        if _UNSAFE_PATH.search(org_name):
            raise ConfigError(
                f"ado_organizations entry contains unsafe characters: {org_name!r}"
            )

    for entry in resource_scopes:
        if not entry.startswith("/subscriptions/"):
            raise ConfigError(f"resource_scopes entry must start with '/subscriptions/': {entry!r}")

    if not (tenants or management_groups or subscriptions or resource_scopes or ado_organizations):
        raise ConfigError("engagement scope is empty — refuse to run (unset scope)")

    allow_write = raw.get("allow_write", False)
    if not isinstance(allow_write, bool):
        raise ConfigError("allow_write must be a boolean (true/false)")

    authorization_ref = raw.get("authorization_ref", "")
    if not isinstance(authorization_ref, str):
        raise ConfigError("authorization_ref must be a string")

    return EngagementConfig(
        engagement=_req_str(raw, "engagement"),
        authorization_ref=authorization_ref,
        window_start=window_start,
        window_end=window_end,
        tenants=tenants,
        management_groups=management_groups,
        subscriptions=subscriptions,
        resource_scopes=resource_scopes,
        ado_organizations=ado_organizations,
        allow_write=allow_write,
        window_explicit=window_explicit,
    )


def _req_str(raw: Mapping[str, Any], key: str) -> str:
    val = raw.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ConfigError(f"engagement config missing required '{key}'")
    return val


def _parse_dt(val: Any, field: str) -> datetime:
    if isinstance(val, datetime):
        dt = val
    elif isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ConfigError(f"{field} is not an ISO-8601 datetime: {val!r}") from exc
    elif val is None:
        raise ConfigError(f"{field} is required (ISO-8601 datetime)")
    else:
        raise ConfigError(f"{field} must be an ISO-8601 datetime string, got {type(val).__name__}")
    if dt.tzinfo is None:
        raise ConfigError(
            f"{field} is a naive datetime (no timezone); use ISO-8601 with timezone "
            f"(e.g. '{dt.isoformat()}Z' for UTC)"
        )
    return dt.astimezone(UTC)


def _str_set(val: Any, field: str) -> frozenset[str]:
    items = _str_tuple(val, field)
    return frozenset(items)


def _str_tuple(val: Any, field: str) -> tuple[str, ...]:
    if val is None:
        return ()
    if not isinstance(val, list) or not all(isinstance(x, str) and x.strip() for x in val):
        raise ConfigError(f"{field} must be a list of non-empty strings")
    return tuple(val)


# ---------------------------------------------------------------------------
# Interactive config bootstrapper
# ---------------------------------------------------------------------------


@dataclass
class _BootstrapData:
    engagement: str = ""
    authorization_ref: str = ""
    tenants: list[str] | None = None
    management_groups: list[str] | None = None
    subscriptions: list[str] | None = None
    resource_scopes: list[str] | None = None
    ado_organizations: list[str] | None = None
    window_days: int = 90


def bootstrap_config(
    path: str | Path | None = None,
    *,
    engagement: str | None = None,
    ado_organizations: list[str] | None = None,
    tenants: list[str] | None = None,
    subscriptions: list[str] | None = None,
) -> Path:
    """Create an engagement config file interactively or from arguments.

    When called without keyword arguments, runs a guided setup that walks the
    operator through every config field with explanations. When called with
    keyword arguments (programmatic mode), skips prompts for provided fields.
    Returns the path to the written config file.
    """
    resolved = resolve_config_path(path)
    programmatic = any(
        v is not None for v in (engagement, ado_organizations, tenants, subscriptions)
    )

    if programmatic:
        return _bootstrap_programmatic(
            resolved,
            engagement=engagement or "",
            ado_organizations=ado_organizations or [],
            tenants=tenants or [],
            subscriptions=subscriptions or [],
        )
    return _bootstrap_interactive(resolved)


def _bootstrap_programmatic(
    resolved: Path,
    *,
    engagement: str,
    ado_organizations: list[str],
    tenants: list[str],
    subscriptions: list[str],
) -> Path:
    if not engagement:
        raise ConfigError("engagement name is required")
    if not (ado_organizations or tenants or subscriptions):
        raise ConfigError(
            "at least one scope dimension is required"
            " (ado_organizations, tenants, or subscriptions)"
        )
    data = _BootstrapData(
        engagement=engagement,
        ado_organizations=ado_organizations or None,
        tenants=tenants or None,
        subscriptions=subscriptions or None,
    )
    resolved.write_text(_render_config(data))
    return resolved


def _bootstrap_interactive(resolved: Path) -> Path:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule

    con = Console()

    con.print()
    con.print(Panel(
        "[bold]Engagement Setup[/]\n\n"
        "All operations are constrained to the scope defined here.\n"
        "Nothing runs without it.",
        border_style="blue",
        padding=(1, 2),
    ))

    data = _BootstrapData()

    # -- 1. Engagement identity --
    con.print()
    con.print(Rule("[bold]Engagement Identity[/]", style="cyan"))
    data.engagement = _prompt(
        con, "Engagement name",
        hint="e.g. ACME-2026-Q2",
        required=True,
    )
    data.authorization_ref = _prompt(
        con, "Authorization ref",
        hint="SOW/RoE number — Enter to skip",
        required=False,
    )

    # -- 2. ADO scope --
    con.print()
    con.print(Rule("[bold]ADO Scope[/]", style="cyan"))
    con.print("  [dim]Organization this engagement is authorized to assess.[/]")
    data.ado_organizations = _prompt_list(
        con, "ADO Org Name",
        hint="comma-separated, e.g. acme-eng, acme-prod",
        required=True,
    )

    # -- ADO Authentication --
    con.print()
    con.print(Rule("[bold]ADO Authentication[/]", style="cyan"))
    con.print("  [dim]Paste your PAT (input is masked).[/]")
    while True:
        pat_value = _read_pat("  ADO PAT: ")
        if pat_value:
            break
        con.print("  [red]PAT is required.[/]")

    org = data.ado_organizations[0] if data.ado_organizations else None
    if org:
        con.print("  [dim]Validating PAT…[/]", end="")
        ok, detail = _validate_ado_pat(pat_value, org)
        if ok:
            con.print(f"\r  [green]PAT valid — authenticated to {org}[/]")
        else:
            con.print(f"\r  [red]PAT validation failed: {detail}[/]")
            raise ConfigError(f"PAT validation failed: {detail}")

    from beachhead.core.auth.ado_pat import _store_pat_sync

    _store_pat_sync(pat_value)
    con.print("  [green]PAT stored.[/]")

    # -- Testing window --
    con.print()
    con.print(Rule("[bold]Testing Window[/]", style="cyan"))
    con.print("  [dim]Number of days from today the engagement is authorized.[/]")
    data.window_days = _prompt_int(con, "Window (days)", default=90)

    # -- Review + confirm --
    con.print()
    con.print(Rule("[bold]Review[/]", style="green"))
    con.print()
    con.print(f"  [bold]Engagement[/]    {data.engagement}")
    if data.authorization_ref:
        con.print(f"  [bold]Authorization[/] {data.authorization_ref}")
    if data.ado_organizations:
        con.print(f"  [bold]ADO orgs[/]      {', '.join(data.ado_organizations)}")
    con.print(f"  [bold]Window[/]        {data.window_days} days from now")
    if data.tenants or data.subscriptions or data.management_groups or data.resource_scopes:
        azure_parts: list[str] = []
        if data.tenants:
            azure_parts.append(f"{len(data.tenants)} tenant(s)")
        if data.subscriptions:
            azure_parts.append(f"{len(data.subscriptions)} subscription(s)")
        if data.management_groups:
            azure_parts.append(f"{len(data.management_groups)} mgmt group(s)")
        if data.resource_scopes:
            azure_parts.append(f"{len(data.resource_scopes)} resource scope(s)")
        con.print(f"  [dim]Azure scope[/]   {', '.join(azure_parts)}")
    con.print(f"  [dim]Config path[/]   {resolved}")
    con.print()

    if not _prompt_yn(con, "Write this config?", default=True):
        raise ConfigError("config creation cancelled")

    resolved.write_text(_render_config(data))
    return resolved


def _render_config(data: _BootstrapData) -> str:
    now = datetime.now(tz=UTC)
    end = now + timedelta(days=data.window_days)

    config: dict[str, Any] = {"engagement": data.engagement}

    if data.authorization_ref:
        config["authorization_ref"] = data.authorization_ref

    config["window"] = {
        "start": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if data.ado_organizations:
        config["ado_organizations"] = data.ado_organizations
    if data.tenants:
        config["tenants"] = data.tenants
    if data.management_groups:
        config["management_groups"] = data.management_groups
    if data.subscriptions:
        config["subscriptions"] = data.subscriptions
    if data.resource_scopes:
        config["resource_scopes"] = data.resource_scopes

    header = "# Beachhead engagement scope config\n# See docs/opsec-and-scope.md for all options.\n"
    return header + yaml.dump(config, default_flow_style=False, sort_keys=False)


def _prompt(
    con: Console, label: str, *, hint: str, required: bool
) -> str:
    if required:
        con.print(f"  [bold]{label}[/]: ", end="")
    else:
        con.print(f"  [bold]{label}[/] [dim]({hint})[/]: ", end="")
    try:
        value = input("").strip()
    except (EOFError, KeyboardInterrupt):
        raise ConfigError("config creation cancelled") from None
    if required and not value:
        raise ConfigError(f"{label} is required")
    return value


def _prompt_list(
    con: Console, label: str, *, hint: str, required: bool = False
) -> list[str] | None:
    raw = _prompt(con, label, hint=hint, required=required)
    if not raw:
        return None
    return [v.strip() for v in raw.split(",") if v.strip()]


def _prompt_int(con: Console, label: str, *, default: int) -> int:
    con.print(f"  [bold]{label}[/] [dim](default {default})[/]: ", end="")
    try:
        raw = input("").strip()
    except (EOFError, KeyboardInterrupt):
        raise ConfigError("config creation cancelled") from None
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        raise ConfigError(f"{label} must be a number") from None
    if val < 1:
        raise ConfigError(f"{label} must be at least 1")
    return val


def _prompt_yn(con: Console, label: str, *, default: bool) -> bool:
    default_hint = "yes" if default else "no"
    con.print(
        f"  [bold]{label}[/] [dim](y/n, default {default_hint})[/]: ",
        end="",
    )
    try:
        raw = input("").strip().lower()
    except (EOFError, KeyboardInterrupt):
        raise ConfigError("config creation cancelled") from None
    if not raw:
        return default
    return raw in ("y", "yes")


def _validate_ado_pat(pat: str, org: str) -> tuple[bool, str]:
    """List one project to verify the PAT authenticates against the org."""
    import base64

    import httpx

    if _UNSAFE_PATH.search(org):
        return False, f"org name contains unsafe characters: {org!r}"

    token = base64.b64encode(f":{pat}".encode()).decode()
    url = f"https://dev.azure.com/{org}/_apis/projects"
    try:
        resp = httpx.get(
            url,
            params={"$top": "1", "api-version": "7.1"},
            headers={"Authorization": f"Basic {token}"},
            follow_redirects=False,
            timeout=10,
        )
        if resp.status_code == 200:
            return True, ""
        if resp.status_code in (301, 302, 303, 401):
            return False, "unauthorized — bad or expired PAT"
        if resp.status_code == 403:
            return False, "PAT lacks access to this org"
        return False, f"HTTP {resp.status_code}"
    except httpx.ConnectError:
        return False, "connection failed — check network"
    except httpx.TimeoutException:
        return False, "request timed out"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _read_pat(prompt: str) -> str:
    from beachhead.core.auth.ado_pat import read_pat

    return read_pat(prompt)
