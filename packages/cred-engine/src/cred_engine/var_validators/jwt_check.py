"""JWT token validation — offline decode and expiry check."""

from __future__ import annotations

import base64
import json
import time

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)


def _b64_decode(segment: str) -> bytes:
    padded = segment + "=" * (4 - len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def validate_jwt(target: CredentialTarget) -> ValidationResult:
    """Decode a JWT and check its expiry claim. Entirely offline."""
    value = target.value.strip()

    parts = value.split(".")
    if len(parts) < 2:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.JWT,
            detail="Not a valid JWT structure (expected header.payload.signature)",
        )

    try:
        header = json.loads(_b64_decode(parts[0]))
    except Exception:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.JWT,
            detail="Failed to decode JWT header",
        )

    try:
        payload = json.loads(_b64_decode(parts[1]))
    except Exception:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.JWT,
            detail="Failed to decode JWT payload",
        )

    now = int(time.time())
    exp = payload.get("exp")
    iss = payload.get("iss", "")
    sub = payload.get("sub", "")
    aud = payload.get("aud", "")

    metadata: dict[str, object] = {
        "algorithm": header.get("alg", "unknown"),
        "issuer": iss,
        "subject": sub,
        "audience": aud,
    }

    if "nbf" in payload:
        metadata["not_before"] = payload["nbf"]

    if exp is None:
        return ValidationResult(
            target=target,
            status=ValidationStatus.UNKNOWN,
            credential_type=CredentialType.JWT,
            detail="JWT has no expiry claim — may be long-lived",
            identity=sub or iss,
            metadata=metadata,
        )

    metadata["expires_at"] = exp

    if exp < now:
        age_hours = (now - exp) / 3600
        return ValidationResult(
            target=target,
            status=ValidationStatus.EXPIRED,
            credential_type=CredentialType.JWT,
            detail=f"JWT expired {age_hours:.1f} hours ago",
            identity=sub or iss,
            metadata=metadata,
        )

    remaining_hours = (exp - now) / 3600
    return ValidationResult(
        target=target,
        status=ValidationStatus.VALID,
        credential_type=CredentialType.JWT,
        detail=f"JWT valid for {remaining_hours:.1f} more hours",
        identity=sub or iss,
        metadata=metadata,
    )
