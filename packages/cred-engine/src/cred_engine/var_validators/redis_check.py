"""Redis credential validation via redis-cli.

Sends AUTH + PING (read-only) to test the password.
Looks for the host in sibling variables or the value itself.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)
from cred_engine.var_validators.subprocess_util import run_cli

logger = logging.getLogger(__name__)

_HOST_NAMES = frozenset({
    "redis_host", "redis_server", "redis_url", "redis_endpoint",
    "redis_connection", "cache_host", "cache_server",
})

_REDIS_URL_RE = re.compile(r"^rediss?://")


def _parse_redis_url(value: str) -> tuple[str, int, str]:
    """Parse a redis:// URL into (host, port, password)."""
    parsed = urlparse(value)
    host = parsed.hostname or ""
    port = parsed.port or 6379
    password = parsed.password or ""
    return host, port, password


def _find_host(
    all_targets: list[CredentialTarget],
    target: CredentialTarget,
    sibling_vars: dict[str, str],
) -> tuple[str, int]:
    for name, value in sibling_vars.items():
        normalized = name.lower().replace("-", "_").replace(".", "_")
        if normalized in _HOST_NAMES:
            if ":" in value:
                parts = value.rsplit(":", 1)
                try:
                    return parts[0], int(parts[1])
                except ValueError:
                    return value, 6379
            return value, 6379

    for other in all_targets:
        if other is target:
            continue
        same_source = (
            (target.source_pipeline and target.source_pipeline == other.source_pipeline)
            or (target.source_group and target.source_group == other.source_group)
        )
        if same_source:
            normalized = other.variable_name.lower().replace("-", "_").replace(".", "_")
            if normalized in _HOST_NAMES:
                val = other.value
                if ":" in val:
                    parts = val.rsplit(":", 1)
                    try:
                        return parts[0], int(parts[1])
                    except ValueError:
                        return val, 6379
                return val, 6379

    return "", 6379


def validate_redis(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str] | None = None,
) -> ValidationResult:
    """Validate Redis credentials via redis-cli PING (read-only)."""
    siblings = sibling_vars or {}
    value = target.value.strip()

    if _REDIS_URL_RE.match(value):
        host, port, password = _parse_redis_url(value)
    else:
        password = value
        host, port = _find_host(all_targets, target, siblings)

    if not host:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.REDIS_PASSWORD,
            detail="Redis password found but no host in sibling variables",
        )

    args = [
        "redis-cli",
        "-h", host,
        "-p", str(port),
        "-a", password,
        "--no-auth-warning",
        "PING",
    ]

    result = run_cli(args, timeout=10)

    if result.tool_missing:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.REDIS_PASSWORD,
            detail="redis-cli not installed — install via 'brew install redis'",
        )

    if result.timed_out:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.REDIS_PASSWORD,
            detail=f"Connection to '{host}:{port}' timed out",
        )

    combined = result.stdout + result.stderr
    if "PONG" in result.stdout:
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.REDIS_PASSWORD,
            detail=f"Authenticated to Redis at '{host}:{port}'",
            identity=f"redis@{host}:{port}",
            metadata={"host": host, "port": port},
        )

    if "NOAUTH" in combined or "ERR AUTH" in combined or "invalid password" in combined.lower():
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.REDIS_PASSWORD,
            detail=f"Redis rejected password for '{host}:{port}'",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.REDIS_PASSWORD,
        detail=f"redis-cli error: {combined[:200].strip()}",
    )
