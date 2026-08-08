"""LDAP credential validation via ldapwhoami.

Uses ldapwhoami for a read-only bind test. Looks for the LDAP host
and bind DN in sibling variables.
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
    "ldap_host", "ldap_server", "ldap_url", "ldap_endpoint",
    "ldap_uri", "directory_host", "directory_server", "ad_host",
})
_DN_NAMES = frozenset({
    "ldap_bind_dn", "ldap_dn", "bind_dn", "ldap_user",
    "ldap_username", "directory_user", "ad_user", "ad_username",
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


def validate_ldap(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str] | None = None,
) -> ValidationResult:
    """Validate LDAP credentials via ldapwhoami (read-only bind test)."""
    password = target.value.strip()
    siblings = sibling_vars or {}

    host = _find_sibling(_HOST_NAMES, all_targets, target, siblings)
    bind_dn = _find_sibling(_DN_NAMES, all_targets, target, siblings)

    if not host:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.LDAP_BIND_PASSWORD,
            detail="LDAP password found but no host in sibling variables",
        )
    if not bind_dn:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.LDAP_BIND_PASSWORD,
            detail="LDAP password found but no bind DN in sibling variables",
        )

    ldap_url = host if host.startswith("ldap://") or host.startswith("ldaps://") else f"ldap://{host}"

    args = [
        "ldapwhoami",
        "-H", ldap_url,
        "-D", bind_dn,
        "-w", password,
    ]

    result = run_cli(args, timeout=10)

    if result.tool_missing:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.LDAP_BIND_PASSWORD,
            detail=(
                "ldapwhoami not installed — install via "
                "'brew install openldap' or 'apt install ldap-utils'"
            ),
        )

    if result.timed_out:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.LDAP_BIND_PASSWORD,
            detail=f"Connection to '{host}' timed out",
        )

    combined = result.stdout + result.stderr
    if result.returncode == 0 and "dn:" in combined.lower():
        identity = result.stdout.strip()
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.LDAP_BIND_PASSWORD,
            detail=f"LDAP bind successful as '{bind_dn}'",
            identity=identity or bind_dn,
            metadata={"host": host, "bind_dn": bind_dn},
        )

    if "invalid credentials" in combined.lower() or result.returncode == 49:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.LDAP_BIND_PASSWORD,
            detail=f"LDAP bind failed for '{bind_dn}' on '{host}'",
            identity=bind_dn,
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.LDAP_BIND_PASSWORD,
        detail=f"ldapwhoami error: {combined[:200].strip()}",
    )
