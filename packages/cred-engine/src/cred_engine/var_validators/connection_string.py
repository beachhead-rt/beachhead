"""Connection string parsing and component extraction.

Parses SQL, Azure Storage, and Service Bus connection strings into their
components. This is an offline analysis — no connections are attempted.
"""

from __future__ import annotations

import re
from typing import Any

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)

_KV_PATTERN = re.compile(r"([^=;]+)=([^;]*)")


def _parse_kv(conn_str: str) -> dict[str, str]:
    """Parse a semicolon-delimited key=value connection string."""
    result: dict[str, str] = {}
    for match in _KV_PATTERN.finditer(conn_str):
        key = match.group(1).strip()
        value = match.group(2).strip()
        result[key.lower()] = value
    return result


def _identify_service(parts: dict[str, str]) -> tuple[CredentialType, str]:
    """Identify the service type from connection string components."""
    if "accountkey" in parts and ("accountname" in parts or "defaultendpointsprotocol" in parts):
        account = parts.get("accountname", "unknown")
        return CredentialType.AZURE_STORAGE_KEY, f"Azure Storage account '{account}'"

    if "sharedaccesskeyname" in parts or "entitypath" in parts:
        endpoint = parts.get("endpoint", parts.get("sb", "unknown"))
        return CredentialType.AZURE_CONNECTION_STRING, f"Azure Service Bus '{endpoint}'"

    server_keys = {"server", "data source", "datasource"}
    server = ""
    for k in server_keys:
        if k in parts:
            server = parts[k]
            break

    if server and "password" in parts:
        db = parts.get("initial catalog", parts.get("database", "unknown"))
        user = parts.get("user id", parts.get("uid", "unknown"))
        return (
            CredentialType.SQL_CONNECTION_STRING,
            f"SQL Server '{server}' database '{db}' as '{user}'",
        )

    if "password" in parts:
        return CredentialType.GENERIC_PASSWORD, "Unknown service with password"

    return CredentialType.UNKNOWN, "Unrecognized connection string format"


def _redact_parts(parts: dict[str, str]) -> dict[str, str]:
    """Redact sensitive values in parsed connection string."""
    sensitive = {"password", "accountkey", "sharedaccesskey", "sharedsecretvalue"}
    redacted: dict[str, str] = {}
    for k, v in parts.items():
        if k in sensitive:
            redacted[k] = v[:4] + "..." + v[-4:] if len(v) >= 8 else "***"
        else:
            redacted[k] = v
    return redacted


def validate_connection_string(target: CredentialTarget) -> ValidationResult:
    """Parse a connection string and report its components. No live connections."""
    value = target.value.strip()
    parts = _parse_kv(value)

    if not parts:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.UNKNOWN,
            detail="Could not parse as a connection string",
        )

    cred_type, service_desc = _identify_service(parts)
    redacted = _redact_parts(parts)

    metadata: dict[str, Any] = {
        "service": service_desc,
        "components": redacted,
        "has_password": "password" in parts,
        "has_account_key": "accountkey" in parts,
    }

    return ValidationResult(
        target=target,
        status=ValidationStatus.UNKNOWN,
        credential_type=cred_type,
        detail=f"Connection string for {service_desc} (offline parse only — not validated live)",
        metadata=metadata,
    )
