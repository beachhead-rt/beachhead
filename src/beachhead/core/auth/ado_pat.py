"""Acquire an ADO token from a Personal Access Token.

ADO PATs are opaque base64 strings, not JWTs — no ``aud`` claim, no refresh.
The PAT is read from stdin (never the command line — visible in process
listings) and stored as a non-refreshable TokenEntry with audience ``ado``.

Modules retrieve the PAT via ``ctx.auth.get("ado")``, which the
``_ado_common.get_pat()`` helper already calls.

**Accepted risk — PAT memory retention:** Python strings are immutable and not
securely erasable; the PAT remains in process memory until the GC collects it.
This is acceptable for a short-lived operator tool: the PAT lives only for the
engagement session, the process is local, and the alternative (ctypes memset
hacks) is fragile across interpreters. If the threat model changes, consider
storing the PAT in a ``bytearray`` that can be zeroed after use.
"""

from __future__ import annotations

import asyncio
import base64
import time

from beachhead.core.auth.audience import Audience
from beachhead.core.auth.token_entry import TokenEntry
from beachhead.core.errors import AuthError

__all__ = ["acquire_token_ado_pat", "_store_pat_sync", "read_pat"]

_DEFAULT_TTL_S: float = 86400 * 90


# ── masked PAT input ──────────────────────────────────────────────── #

def _star() -> None:
    import sys
    sys.stderr.write("*")
    sys.stderr.flush()


def _erase_char() -> None:
    import sys
    sys.stderr.write("\b \b")
    sys.stderr.flush()


def _read_pat_win() -> list[str]:
    import msvcrt

    chars: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            break
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x08":
            if chars:
                chars.pop()
                _erase_char()
            continue
        chars.append(ch)
        _star()
    return chars


def _read_pat_unix() -> list[str]:
    import sys
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    chars: list[str] = []
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\x04":
                raise EOFError
            if ch in ("\x7f", "\x08"):
                if chars:
                    chars.pop()
                    _erase_char()
                continue
            chars.append(ch)
            _star()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return chars


def read_pat(prompt: str) -> str:
    """Read a PAT with ``*`` feedback per keystroke. Enter submits."""
    import sys

    sys.stderr.write(prompt)
    sys.stderr.flush()

    chars: list[str] = []
    try:
        if sys.platform == "win32":
            chars = _read_pat_win()
        else:
            chars = _read_pat_unix()
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write("\n")
        sys.stderr.flush()
        return ""

    sys.stderr.write("\n")
    sys.stderr.flush()
    return "".join(chars).strip()


def _resolve_pat_identity(pat: str) -> str | None:
    """Call the ADO connectionData API to get the authenticated user's display name."""
    import httpx

    token = base64.b64encode(f":{pat}".encode()).decode()
    try:
        resp = httpx.get(
            "https://app.vssps.visualstudio.com/_apis/connectionData",
            headers={"Authorization": f"Basic {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            user = data.get("authenticatedUser", {})
            return (
                user.get("providerDisplayName")
                or user.get("customDisplayName")
                or None
            )
    except Exception:  # noqa: BLE001
        pass
    return None


async def acquire_token_ado_pat(
    pat: str,
    *,
    expires_at: float | None = None,
) -> TokenEntry:
    """Wrap a raw ADO PAT string into a TokenEntry.

    Validates the PAT against ADO and resolves the authenticated identity.
    ``pat`` must be non-empty. Callers are responsible for reading
    it from a safe source (stdin, env, keyring) — never the command line.
    """
    pat = pat.strip()
    if not pat:
        raise AuthError("ADO PAT must not be empty")

    display_name = await asyncio.to_thread(_resolve_pat_identity, pat)

    return TokenEntry(
        access_token=pat,
        audience=Audience.ADO,
        expires_at=expires_at or (time.time() + _DEFAULT_TTL_S),
        source="ado_pat",
        display_name=display_name,
    )


def _store_pat_sync(pat: str) -> None:
    """Store an ADO PAT in the token cache (sync, safe from inside an event loop)."""
    from beachhead.core.auth.token_cache import load_tokens, save_tokens

    pat = pat.strip()
    if not pat:
        raise AuthError("ADO PAT must not be empty")

    display_name = _resolve_pat_identity(pat)

    entry = TokenEntry(
        access_token=pat,
        audience=Audience.ADO,
        expires_at=time.time() + _DEFAULT_TTL_S,
        source="ado_pat",
        display_name=display_name,
    )
    existing = load_tokens()
    existing[entry.audience] = entry
    save_tokens(existing)
