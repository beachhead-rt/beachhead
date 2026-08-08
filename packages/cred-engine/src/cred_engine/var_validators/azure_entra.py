"""Azure Entra ID (AAD) client secret validation.

Requests a token via the OAuth2 client_credentials flow (read-only).
Requires tenant_id and client_id from sibling variables.
"""

from __future__ import annotations

import logging

import httpx

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

_TENANT_NAMES = frozenset({
    "tenant_id", "tenantid", "azure_tenant_id", "aad_tenant_id",
    "azure_tenant", "arm_tenant_id", "directory_id",
})
_CLIENT_NAMES = frozenset({
    "client_id", "clientid", "azure_client_id", "app_id", "appid",
    "application_id", "applicationid", "arm_client_id", "service_principal_id",
})


def _find_sibling(
    names: frozenset[str],
    all_targets: list[CredentialTarget],
    target: CredentialTarget,
    sibling_vars: dict[str, str],
) -> str:
    """Find a sibling variable by name hint."""
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


def validate_entra_secret(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str] | None = None,
) -> ValidationResult:
    """Validate an Azure Entra client secret via client_credentials token request."""
    client_secret = target.value.strip()
    siblings = sibling_vars or {}

    tenant_id = _find_sibling(_TENANT_NAMES, all_targets, target, siblings)
    client_id = _find_sibling(_CLIENT_NAMES, all_targets, target, siblings)

    if not tenant_id or not client_id:
        missing = []
        if not tenant_id:
            missing.append("tenant_id")
        if not client_id:
            missing.append("client_id")
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.AZURE_ENTRA_SECRET,
            detail=(
                f"Client secret found but missing sibling variable(s): "
                f"{', '.join(missing)}"
            ),
        )

    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    try:
        resp = httpx.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.AZURE_ENTRA_SECRET,
            detail=f"HTTP error: {exc}",
        )

    if resp.status_code == 200:
        data = resp.json()
        scopes = data.get("scope", "").split()
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.AZURE_ENTRA_SECRET,
            detail=f"Valid client credentials for tenant '{tenant_id}'",
            identity=f"{client_id}@{tenant_id}",
            scopes=scopes,
            metadata={
                "tenant_id": tenant_id,
                "client_id": client_id,
                "token_type": data.get("token_type", ""),
                "expires_in": data.get("expires_in", 0),
            },
        )

    if resp.status_code == 401 or resp.status_code == 400:
        error = resp.json().get("error_description", "rejected")
        if "expired" in error.lower():
            return ValidationResult(
                target=target,
                status=ValidationStatus.EXPIRED,
                credential_type=CredentialType.AZURE_ENTRA_SECRET,
                detail=f"Client secret expired: {error.split(chr(10))[0]}",
                identity=f"{client_id}@{tenant_id}",
            )
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.AZURE_ENTRA_SECRET,
            detail=f"Credentials rejected: {error.split(chr(10))[0]}",
            identity=f"{client_id}@{tenant_id}",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.AZURE_ENTRA_SECRET,
        detail=f"Unexpected response (HTTP {resp.status_code})",
    )
