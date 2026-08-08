"""GitHub PAT and app token validation."""

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

_GITHUB_API = "https://api.github.com"


def validate_github_pat(target: CredentialTarget) -> ValidationResult:
    """Validate a GitHub PAT by calling GET /user."""
    token = target.value.strip()
    cred_type = (
        CredentialType.GITHUB_APP_TOKEN
        if token.startswith("ghs_")
        else CredentialType.GITHUB_PAT
    )

    try:
        resp = httpx.get(
            f"{_GITHUB_API}/user",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=cred_type,
            detail=f"HTTP error: {exc}",
        )

    if resp.status_code == 200:
        data = resp.json()
        login = data.get("login", "")
        name = data.get("name", "")

        scopes = resp.headers.get("x-oauth-scopes", "").split(", ")
        scopes = [s for s in scopes if s]

        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=cred_type,
            detail=f"Authenticated as {login}" + (f" ({name})" if name else ""),
            identity=login,
            scopes=scopes,
            metadata={
                "user_id": data.get("id"),
                "type": data.get("type", ""),
                "two_factor": data.get("two_factor_authentication"),
            },
        )

    if resp.status_code == 401:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=cred_type,
            detail="Token rejected — expired or revoked",
        )

    if resp.status_code == 403:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=cred_type,
            detail=f"Token forbidden — {resp.json().get('message', 'rate limited or IP blocked')}",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=cred_type,
        detail=f"Unexpected status {resp.status_code}",
    )
