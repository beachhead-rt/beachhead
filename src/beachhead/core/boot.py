"""RunEnv bootstrap — assemble a fully-wired RunEnv from config + auth.

Called by both the CLI (``bh <phase> run``) and the TUI module runner.
Opens a writable store, resolves scope, constructs clients, and returns
a RunEnv ready for ``run_module()``. The caller owns the RunEnv lifetime
and must close the store when done.
"""

from __future__ import annotations

import getpass
import logging
from datetime import UTC, datetime

from rich.console import Console

from beachhead.core.audit import AuditLog
from beachhead.core.auth.broker import AuthBroker
from beachhead.core.clients.az_client import AzSubprocessClient
from beachhead.core.config import load_config
from beachhead.core.runner import RunEnv
from beachhead.core.scope import ScopeGuard, resolve_scope
from beachhead.core.secret_store import open_secret_store, secret_store_path
from beachhead.core.store.engine import open_store

__all__ = ["bootstrap_run_env"]

_log = logging.getLogger(__name__)

_BOOT_RUN_ID = "__boot__"


def _load_cached_tokens(broker: AuthBroker) -> None:
    """Load tokens from the file cache into the broker, skipping individual failures."""
    try:
        from beachhead.core.auth.token_cache import load_tokens

        entries = load_tokens()
    except Exception:  # noqa: BLE001
        _log.debug("token cache load failed", exc_info=True)
        return

    for aud, entry in entries.items():
        try:
            broker.add(
                entry.access_token,
                entry.audience,
                expires_at=entry.expires_at,
                refresh_token=entry.refresh_token,
                source=entry.source,
                client_id=entry.client_id,
                tenant_id=entry.tenant_id,
                scopes=entry.scopes,
            )
        except Exception:  # noqa: BLE001
            _log.debug("failed to load cached token for %s", aud, exc_info=True)


async def bootstrap_run_env(
    store_path: str,
    config_path: str | None = None,
    *,
    auth: AuthBroker | None = None,
    console: Console | None = None,
    operator: str | None = None,
    passphrase: str | None = None,
) -> RunEnv:
    """Build a RunEnv ready for module execution.

    Opens a **writable** store (creates if needed), loads config, resolves scope,
    and wires the az client.

    If ``auth`` is None, the broker starts empty (useful for analyze modules which
    make no API calls). The caller should add tokens to the broker before running
    enumerate/harvest modules.
    """
    con = console or Console()
    config = load_config(config_path)

    store = open_store(store_path)
    secrets = None
    try:
        if passphrase:
            secrets = open_secret_store(secret_store_path(store_path), passphrase)
        store.ensure_engagement(name=config.engagement, scope_hash=config.scope_hash)

        resolved = await resolve_scope(config, clock=lambda: datetime.now(UTC))
        guard = ScopeGuard(resolved, clock=lambda: datetime.now(UTC))

        op = operator or getpass.getuser()

        effective_auth = auth or AuthBroker()
        if auth is None:
            _load_cached_tokens(effective_auth)
        boot_audit = AuditLog(store, operator=op, run_id=_BOOT_RUN_ID)

        orgs = config.ado_organizations
        default_org = min(orgs) if orgs else None

        subs = config.subscriptions
        default_sub = min(subs) if subs else None

        az = AzSubprocessClient(
            scope=guard,
            audit=boot_audit,
            default_subscription=default_sub,
            default_organization=default_org,
        )
    except Exception:
        if secrets is not None:
            secrets.close()
        store.close()
        raise

    return RunEnv(
        store=store,
        az=az,
        auth=effective_auth,
        config=config,
        scope=guard,
        console=con,
        operator=op,
        secrets=secrets,
    )
