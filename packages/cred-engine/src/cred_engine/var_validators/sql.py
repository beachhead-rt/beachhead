"""SQL Server credential validation via sqlcmd.

Attempts a read-only SELECT 1 query to test authentication.
Falls back to the connection_string parser if sqlcmd is not installed.
"""

from __future__ import annotations

import logging
import re

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)
from cred_engine.var_validators.subprocess_util import run_cli

logger = logging.getLogger(__name__)

_KV_RE = re.compile(r"([^=;]+)=([^;]*)")


def _parse_sql_parts(value: str) -> dict[str, str]:
    parts: dict[str, str] = {}
    for m in _KV_RE.finditer(value):
        parts[m.group(1).strip().lower()] = m.group(2).strip()
    return parts


def validate_sql(target: CredentialTarget) -> ValidationResult:
    """Validate SQL Server credentials via sqlcmd (read-only SELECT 1)."""
    parts = _parse_sql_parts(target.value)

    server_keys = {"server", "data source", "datasource"}
    server = ""
    for k in server_keys:
        if k in parts:
            server = parts[k]
            break

    password = parts.get("password", "")
    user = parts.get("user id", parts.get("uid", ""))
    database = parts.get("initial catalog", parts.get("database", ""))

    if not server or not password:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.SQL_CONNECTION_STRING,
            detail="Could not extract server/password from connection string",
        )

    args = [
        "sqlcmd",
        "-S", server,
        "-U", user or "sa",
        "-P", password,
        "-Q", "SELECT 1",
        "-l", "10",
    ]
    if database:
        args.extend(["-d", database])

    result = run_cli(args, timeout=15)

    if result.tool_missing:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.SQL_CONNECTION_STRING,
            detail=(
                "sqlcmd not installed — install via "
                "'brew install sqlcmd' or 'apt install mssql-tools18'"
            ),
        )

    if result.timed_out:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.SQL_CONNECTION_STRING,
            detail=f"Connection to '{server}' timed out",
        )

    combined = result.stdout + result.stderr
    if result.returncode == 0 and "1" in result.stdout:
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.SQL_CONNECTION_STRING,
            detail=f"Authenticated to '{server}' as '{user or 'sa'}'",
            identity=f"{user or 'sa'}@{server}",
            metadata={
                "server": server,
                "user": user or "sa",
                "database": database or "(default)",
            },
        )

    if "login failed" in combined.lower():
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.SQL_CONNECTION_STRING,
            detail=f"Login failed for '{user or 'sa'}' on '{server}'",
            identity=f"{user or 'sa'}@{server}",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.SQL_CONNECTION_STRING,
        detail=f"sqlcmd error: {combined[:200].strip()}",
    )
