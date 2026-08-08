"""Azure Storage credential validation via REST API.

Uses SharedKey authentication to call List Containers (read-only).
Handles both connection-string and standalone account key + name.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import logging
import re

import httpx

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

_API_VERSION = "2023-11-03"
_KV_RE = re.compile(r"([^=;]+)=([^;]*)")


def _parse_connection_string(value: str) -> tuple[str, str]:
    """Extract AccountName and AccountKey from a connection string."""
    parts: dict[str, str] = {}
    for m in _KV_RE.finditer(value):
        parts[m.group(1).strip().lower()] = m.group(2).strip()
    return parts.get("accountname", ""), parts.get("accountkey", "")


def _shared_key_header(
    account: str, key_b64: str, verb: str, path: str, date: str
) -> str:
    """Build a SharedKey Authorization header value."""
    canonicalized_headers = (
        f"x-ms-date:{date}\nx-ms-version:{_API_VERSION}\n"
    )
    canonicalized_resource = f"/{account}/{path}\ncomp:list\nrestype:container"

    string_to_sign = (
        f"{verb}\n"   # VERB
        "\n"           # Content-Encoding
        "\n"           # Content-Language
        "\n"           # Content-Length
        "\n"           # Content-MD5
        "\n"           # Content-Type
        "\n"           # Date
        "\n"           # If-Modified-Since
        "\n"           # If-Match
        "\n"           # If-None-Match
        "\n"           # If-Unmodified-Since
        "\n"           # Range
        f"{canonicalized_headers}"
        f"{canonicalized_resource}"
    )

    key_bytes = base64.b64decode(key_b64)
    sig = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {account}:{sig}"


def validate_azure_storage(target: CredentialTarget) -> ValidationResult:
    """Validate Azure Storage credentials by listing containers (read-only)."""
    account, key = _parse_connection_string(target.value)
    if not account or not key:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.AZURE_STORAGE_KEY,
            detail="Could not extract AccountName/AccountKey from value",
        )

    now = datetime.datetime.now(tz=datetime.UTC)
    date_str = now.strftime("%a, %d %b %Y %H:%M:%S GMT")

    url = (
        f"https://{account}.blob.core.windows.net/"
        f"?comp=list&restype=container&maxresults=1"
    )

    try:
        auth = _shared_key_header(account, key, "GET", "", date_str)
        resp = httpx.get(
            url,
            headers={
                "x-ms-date": date_str,
                "x-ms-version": _API_VERSION,
                "Authorization": auth,
            },
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.AZURE_STORAGE_KEY,
            detail=f"HTTP error: {exc}",
        )

    if resp.status_code == 200:
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.AZURE_STORAGE_KEY,
            detail=f"Valid storage key for account '{account}'",
            identity=account,
            metadata={"account_name": account},
        )

    if resp.status_code == 403:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.AZURE_STORAGE_KEY,
            detail=f"Storage key rejected for account '{account}'",
        )

    if resp.status_code == 404:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.AZURE_STORAGE_KEY,
            detail=f"Storage account '{account}' not found",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.AZURE_STORAGE_KEY,
        detail=f"Unexpected response (HTTP {resp.status_code})",
    )
