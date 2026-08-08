"""Finding suppression via allowlist — exclude known-good credential matches."""

from __future__ import annotations

import json
import logging
from fnmatch import fnmatch
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path(".credscan-allowlist.json")


def load_allowlist(path: Path | None = None) -> list[dict[str, str]]:
    """Load allowlist entries from a JSON file.

    File format::

        {
          "allowlist": [
            {"repo": "my-repo", "path": "src/config.json"},
            {"repo": "test-*", "pattern": "SQL Connection String"},
            {"pattern": "Generic Password Assignment", "reason": "too noisy"},
            {"path": "*/node_modules/*"}
          ]
        }

    Each entry can have ``repo``, ``path``, and/or ``pattern`` fields
    (fnmatch globs supported). An entry matches when ALL specified fields
    match. The ``reason`` field is informational only.
    """
    target = path or _DEFAULT_PATH
    if not target.exists():
        return []
    try:
        data = json.loads(target.read_text())
        entries = data.get("allowlist", [])
        if not isinstance(entries, list):
            logger.warning("Allowlist 'allowlist' key is not a list in %s", target)
            return []
        return [e for e in entries if isinstance(e, dict)]
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load allowlist %s: %s", target, exc)
        return []


def is_suppressed(
    entries: list[dict[str, str]],
    *,
    repo: str = "",
    file_path: str = "",
    pattern_name: str = "",
) -> bool:
    """Check if a finding matches any allowlist entry.

    An entry matches when every field it specifies matches the finding.
    Fields support fnmatch globs (``*``, ``?``, ``[seq]``).
    An entry with no matching fields is ignored.
    """
    if not entries:
        return False

    for entry in entries:
        entry_repo = entry.get("repo", "")
        entry_path = entry.get("path", "")
        entry_pattern = entry.get("pattern", "")

        if not entry_repo and not entry_path and not entry_pattern:
            continue

        matched = True
        if entry_repo and not fnmatch(repo.lower(), entry_repo.lower()):
            matched = False
        if entry_path and not fnmatch(file_path.lower(), entry_path.lower()):
            matched = False
        if entry_pattern and not fnmatch(pattern_name.lower(), entry_pattern.lower()):
            matched = False

        if matched:
            return True

    return False
