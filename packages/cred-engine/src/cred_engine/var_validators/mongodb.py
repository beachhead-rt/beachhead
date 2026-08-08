"""MongoDB credential validation via mongosh.

Runs a read-only ping command to test authentication.
Expects a mongodb:// or mongodb+srv:// connection URI.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)
from cred_engine.var_validators.subprocess_util import run_cli

logger = logging.getLogger(__name__)

_MONGO_URL_RE = re.compile(r"^mongodb(\+srv)?://")


def validate_mongodb(target: CredentialTarget) -> ValidationResult:
    """Validate MongoDB credentials via mongosh ping (read-only)."""
    uri = target.value.strip()

    if not _MONGO_URL_RE.match(uri):
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.MONGODB_CONNECTION,
            detail="Value is not a mongodb:// connection URI",
        )

    parsed = urlparse(uri)
    host = parsed.hostname or "unknown"
    user = parsed.username or ""

    args = [
        "mongosh",
        uri,
        "--eval", "db.runCommand({ping: 1})",
        "--quiet",
    ]

    result = run_cli(args, timeout=15)

    if result.tool_missing:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.MONGODB_CONNECTION,
            detail=(
                "mongosh not installed — install via "
                "'brew install mongosh' or 'npm install -g mongosh'"
            ),
        )

    if result.timed_out:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.MONGODB_CONNECTION,
            detail=f"Connection to '{host}' timed out",
        )

    combined = result.stdout + result.stderr
    if result.returncode == 0 and "ok" in combined.lower():
        identity = f"{user}@{host}" if user else host
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.MONGODB_CONNECTION,
            detail=f"Authenticated to MongoDB at '{host}'",
            identity=identity,
            metadata={"host": host, "user": user},
        )

    if "authentication failed" in combined.lower():
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.MONGODB_CONNECTION,
            detail=f"MongoDB authentication failed for '{user}@{host}'",
            identity=f"{user}@{host}" if user else host,
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.MONGODB_CONNECTION,
        detail=f"mongosh error: {combined[:200].strip()}",
    )
