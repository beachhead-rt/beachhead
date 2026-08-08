"""SendGrid API key validation."""

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


def validate_sendgrid_key(target: CredentialTarget) -> ValidationResult:
    """Validate a SendGrid API key by calling GET /v3/scopes."""
    key = target.value.strip()

    try:
        resp = httpx.get(
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {key}"},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.SENDGRID_KEY,
            detail=f"HTTP error: {exc}",
        )

    if resp.status_code == 200:
        data = resp.json()
        scopes = data.get("scopes", [])
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.SENDGRID_KEY,
            detail=f"Valid key with {len(scopes)} scope(s)",
            scopes=scopes[:20],
        )

    if resp.status_code in (401, 403):
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.SENDGRID_KEY,
            detail="Key rejected — invalid or revoked",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.SENDGRID_KEY,
        detail=f"Unexpected status {resp.status_code}",
    )
