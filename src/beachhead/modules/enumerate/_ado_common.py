"""Shared bootstrapping for ADO modules (enumerate, harvest, exploit)."""

from __future__ import annotations

import logging
import os
import re

from beachhead.core.clients.ado_search import AdoSearchClient
from beachhead.core.errors import AuthError
from beachhead.core.module import RunContext, RunResult

logger = logging.getLogger(__name__)

HTML_TAG_RE = re.compile(r"<[^>]+>")


async def get_pat(ctx: RunContext) -> str | None:
    env_pat = os.environ.get("BEACHHEAD_ADO_PAT")
    if env_pat:
        return env_pat
    if ctx.auth is not None:
        try:
            return await ctx.auth.get("ado")
        except AuthError as exc:
            logger.debug("auth broker has no ADO token: %s", exc)

    try:
        from beachhead.core.auth.token_cache import load_tokens

        entry = load_tokens().get("ado")
        if entry is not None:
            return entry.access_token
    except Exception:  # noqa: BLE001
        logger.debug("token cache fallback failed", exc_info=True)
    return None


def get_orgs(ctx: RunContext) -> list[str]:
    cfg = ctx.config
    ado_orgs = getattr(cfg, "ado_organizations", None)
    return list(ado_orgs) if ado_orgs is not None else []


def no_pat_result(ctx: RunContext) -> RunResult:
    ctx.console.print(
        "[red]No ADO PAT available. Set BEACHHEAD_ADO_PAT or configure auth for 'ado'.[/]"
    )
    return RunResult(ok=False, message="No ADO PAT")


def no_orgs_result(ctx: RunContext) -> RunResult:
    ctx.console.print("[yellow]No ADO organizations in scope config.[/]")
    return RunResult(ok=True, written=0, message="No ADO orgs in scope")


def make_client(org: str, pat: str, ctx: RunContext) -> AdoSearchClient:
    return AdoSearchClient(
        org=org,
        pat=pat,
        scope=ctx.scope,
        audit=ctx.audit,
        run_id=ctx.run_id,
    )
