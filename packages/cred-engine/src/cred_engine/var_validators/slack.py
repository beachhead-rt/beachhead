"""Slack token validation."""

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


def validate_slack_token(target: CredentialTarget) -> ValidationResult:
    """Validate a Slack token by calling auth.test."""
    token = target.value.strip()

    try:
        resp = httpx.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15.0,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.SLACK_TOKEN,
            detail=f"HTTP error: {exc}",
        )

    data = resp.json()
    if data.get("ok"):
        team = data.get("team", "")
        user = data.get("user", "")
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.SLACK_TOKEN,
            detail=f"Valid token for workspace '{team}' as user '{user}'",
            identity=f"{user}@{team}",
            metadata={
                "team_id": data.get("team_id", ""),
                "user_id": data.get("user_id", ""),
                "bot_id": data.get("bot_id", ""),
                "is_enterprise": data.get("is_enterprise_install", False),
            },
        )

    error = data.get("error", "unknown")
    if error in ("invalid_auth", "account_inactive", "token_revoked"):
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.SLACK_TOKEN,
            detail=f"Token rejected: {error}",
        )

    if error == "token_expired":
        return ValidationResult(
            target=target,
            status=ValidationStatus.EXPIRED,
            credential_type=CredentialType.SLACK_TOKEN,
            detail="Token has expired",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.SLACK_TOKEN,
        detail=f"Slack API error: {error}",
    )
