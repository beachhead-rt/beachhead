"""SMTP credential validation via swaks.

Uses swaks --quit-after AUTH to test SMTP authentication without sending
any email (read-only). Looks for host/user in sibling variables.
"""

from __future__ import annotations

import logging

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)
from cred_engine.var_validators.subprocess_util import run_cli

logger = logging.getLogger(__name__)

_HOST_NAMES = frozenset({
    "smtp_host", "smtp_server", "smtp_endpoint", "mail_host",
    "mail_server", "email_host", "email_server", "smtp_url",
})
_USER_NAMES = frozenset({
    "smtp_user", "smtp_username", "smtp_from", "mail_user",
    "mail_username", "email_user", "email_username", "email_address",
    "smtp_login", "mail_from",
})


def _find_sibling(
    names: frozenset[str],
    all_targets: list[CredentialTarget],
    target: CredentialTarget,
    sibling_vars: dict[str, str],
) -> str:
    for name, value in sibling_vars.items():
        if name.lower().replace("-", "_").replace(".", "_") in names:
            return value
    for other in all_targets:
        if other is target:
            continue
        same_source = (
            (target.source_pipeline and target.source_pipeline == other.source_pipeline)
            or (target.source_group and target.source_group == other.source_group)
        )
        if same_source:
            normalized = other.variable_name.lower().replace("-", "_").replace(".", "_")
            if normalized in names:
                return other.value
    return ""


def validate_smtp(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str] | None = None,
) -> ValidationResult:
    """Validate SMTP credentials via swaks --quit-after AUTH (read-only)."""
    password = target.value.strip()
    siblings = sibling_vars or {}

    host = _find_sibling(_HOST_NAMES, all_targets, target, siblings)
    user = _find_sibling(_USER_NAMES, all_targets, target, siblings)

    if not host:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.SMTP_CREDENTIALS,
            detail="SMTP password found but no host in sibling variables",
        )
    if not user:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.SMTP_CREDENTIALS,
            detail="SMTP password found but no username in sibling variables",
        )

    port = "587"
    if ":" in host:
        host, port = host.rsplit(":", 1)

    args = [
        "swaks",
        "--server", host,
        "--port", port,
        "--auth", "LOGIN",
        "--auth-user", user,
        "--auth-password", password,
        "--tls",
        "--quit-after", "AUTH",
        "--timeout", "10",
    ]

    result = run_cli(args, timeout=15)

    if result.tool_missing:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.SMTP_CREDENTIALS,
            detail="swaks not installed — install via 'brew install swaks'",
        )

    if result.timed_out:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.SMTP_CREDENTIALS,
            detail=f"Connection to '{host}:{port}' timed out",
        )

    combined = result.stdout + result.stderr
    if "235" in combined and result.returncode == 0:
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.SMTP_CREDENTIALS,
            detail=f"Authenticated to SMTP '{host}:{port}' as '{user}'",
            identity=f"{user}@{host}",
            metadata={"host": host, "port": port, "user": user},
        )

    if "535" in combined or "authentication failed" in combined.lower():
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.SMTP_CREDENTIALS,
            detail=f"SMTP authentication failed for '{user}' on '{host}'",
            identity=f"{user}@{host}",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.SMTP_CREDENTIALS,
        detail=f"swaks error: {combined[:200].strip()}",
    )
