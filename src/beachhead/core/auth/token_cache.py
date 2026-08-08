"""File-based token cache for cross-command persistence.

Serializes ``TokenEntry`` objects to a JSON file with ``0600`` permissions
so tokens acquired via ``bh auth`` are available to ``bh <phase> run``.

The cache file must live outside the repo tree and be gitignored per
the opsec policy. Access tokens are stored in the clear (necessary for
cross-command use); file permissions are the protection layer.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from beachhead.core.auth.token_entry import KNOWN_AUDIENCES, TokenEntry

__all__ = ["save_tokens", "load_tokens", "default_cache_path"]

_ENV_VAR = "BEACHHEAD_TOKEN_CACHE"
_DEFAULT_FILENAME = ".beachhead-tokens.json"


def default_cache_path() -> Path:
    """Resolve the token cache path from env or default."""
    env = os.environ.get(_ENV_VAR)
    if env:
        return Path(env)
    return Path(_DEFAULT_FILENAME)


def save_tokens(entries: dict[str, TokenEntry], path: Path | None = None) -> Path:
    """Persist token entries to disk with ``0600`` permissions.

    Returns the path written to.
    """
    target = path or default_cache_path()
    data: dict[str, Any] = {}
    for audience, entry in entries.items():
        data[audience] = {
            "access_token": entry.access_token,
            "audience": entry.audience,
            "expires_at": entry.expires_at,
            "source": entry.source,
            "display_name": entry.display_name,
            "refresh_token": entry.refresh_token,
            "client_id": entry.client_id,
            "tenant_id": entry.tenant_id,
            "scopes": list(entry.scopes),
        }

    target.parent.mkdir(parents=True, exist_ok=True)

    tmp = target.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(data, indent=2).encode("utf-8"))
    finally:
        os.close(fd)

    if sys.platform == "win32":
        _restrict_acl_win(tmp)

    os.replace(str(tmp), str(target))

    return target


def load_tokens(path: Path | None = None) -> dict[str, TokenEntry]:
    """Load token entries from the cache file.

    Returns an empty dict if the file does not exist.
    Raises ``ValueError`` if the file exists but is malformed.
    """
    target = path or default_cache_path()
    if not target.is_file():
        return {}

    _check_permissions(target)

    raw = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"token cache is not a JSON object: {target}")

    entries: dict[str, TokenEntry] = {}
    for audience, blob in raw.items():
        if audience not in KNOWN_AUDIENCES:
            continue
        if not isinstance(blob, dict):
            continue
        entries[audience] = TokenEntry(
            access_token=blob["access_token"],
            audience=blob["audience"],
            expires_at=float(blob["expires_at"]),
            source=blob.get("source", "cached"),
            display_name=blob.get("display_name"),
            refresh_token=blob.get("refresh_token"),
            client_id=blob.get("client_id"),
            tenant_id=blob.get("tenant_id"),
            scopes=tuple(blob.get("scopes", ())),
        )

    return entries


def _check_permissions(path: Path) -> None:
    """Warn (but don't block) if the cache file has loose permissions."""
    import sys

    if sys.platform == "win32":
        _check_permissions_win(path)
    else:
        _check_permissions_posix(path)


def _check_permissions_posix(path: Path) -> None:
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            import warnings

            warnings.warn(
                f"token cache {path} has loose permissions ({oct(mode & 0o777)}); expected 0600",
                stacklevel=4,
            )
    except OSError:
        pass


def _restrict_acl_win(path: Path) -> None:
    """Remove inherited ACLs, grant only current user full control."""
    import subprocess

    username = os.environ.get("USERNAME", "")
    if not username:
        return
    try:
        subprocess.run(  # noqa: S603, S607
            ["icacls", str(path), "/inheritance:r",
             "/grant:r", f"{username}:(F)"],
            capture_output=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _check_permissions_win(path: Path) -> None:
    try:
        import subprocess

        result = subprocess.run(  # noqa: S603, S607
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return
        output = result.stdout.lower()
        if "everyone" in output or "builtin\\users" in output:
            import warnings

            warnings.warn(
                f"token cache {path} may be accessible to other users; "
                f"run: icacls \"{path}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
                stacklevel=4,
            )
    except (OSError, subprocess.TimeoutExpired):
        pass
