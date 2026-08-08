"""NPM token validation."""

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


def validate_npm_token(target: CredentialTarget) -> ValidationResult:
    """Validate an NPM token by calling the whoami endpoint."""
    token = target.value.strip()

    try:
        resp = httpx.get(
            "https://registry.npmjs.org/-/whoami",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.NPM_TOKEN,
            detail=f"HTTP error: {exc}",
        )

    if resp.status_code == 200:
        username = resp.json().get("username", "unknown")
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.NPM_TOKEN,
            detail=f"Valid NPM token for user '{username}'",
            identity=username,
        )

    if resp.status_code in (401, 403):
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.NPM_TOKEN,
            detail="Token rejected — invalid or revoked",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.NPM_TOKEN,
        detail=f"Unexpected status {resp.status_code}",
    )
