"""AWS credential validation via STS GetCallerIdentity.

Requires both an Access Key ID and a Secret Access Key. The loader pairs
these from sibling variables in the same pipeline/group.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
from urllib.parse import quote

import httpx

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

_STS_HOST = "sts.amazonaws.com"
_STS_URL = f"https://{_STS_HOST}/"
_SERVICE = "sts"
_REGION = "us-east-1"
_REQUEST_BODY = "Action=GetCallerIdentity&Version=2011-06-15"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _get_signature_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(f"AWS4{secret}".encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def _build_auth_header(access_key: str, secret_key: str) -> dict[str, str]:
    """Build AWS SigV4 signed headers for STS GetCallerIdentity."""
    now = datetime.datetime.now(tz=datetime.UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    content_type = "application/x-www-form-urlencoded; charset=utf-8"
    payload_hash = hashlib.sha256(_REQUEST_BODY.encode()).hexdigest()

    canonical_headers = (
        f"content-type:{content_type}\n"
        f"host:{_STS_HOST}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"

    canonical_request = "\n".join([
        "POST",
        "/",
        "",
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    credential_scope = f"{date_stamp}/{_REGION}/{_SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    signing_key = _get_signature_key(secret_key, date_stamp, _REGION, _SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={quote(access_key, safe='')}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    return {
        "Content-Type": content_type,
        "Host": _STS_HOST,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
    }


def validate_aws_key(
    target: CredentialTarget, secret_key: str
) -> ValidationResult:
    """Validate an AWS access key pair via STS GetCallerIdentity (read-only)."""
    access_key = target.value.strip()

    try:
        headers = _build_auth_header(access_key, secret_key)
        resp = httpx.post(
            _STS_URL,
            content=_REQUEST_BODY,
            headers=headers,
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.AWS_ACCESS_KEY,
            detail=f"HTTP error: {exc}",
        )

    body = resp.text
    if resp.status_code == 200 and "<Arn>" in body:
        arn = _extract_xml(body, "Arn")
        account = _extract_xml(body, "Account")
        user_id = _extract_xml(body, "UserId")
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.AWS_ACCESS_KEY,
            detail=f"Valid AWS credentials — ARN: {arn}",
            identity=arn,
            metadata={
                "account_id": account,
                "user_id": user_id,
                "arn": arn,
            },
        )

    if resp.status_code == 403:
        error_msg = _extract_xml(body, "Message") or "Access denied"
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.AWS_ACCESS_KEY,
            detail=f"AWS rejected credentials: {error_msg}",
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.AWS_ACCESS_KEY,
        detail=f"Unexpected STS response (HTTP {resp.status_code})",
    )


def _extract_xml(xml: str, tag: str) -> str:
    start = xml.find(f"<{tag}>")
    end = xml.find(f"</{tag}>")
    if start == -1 or end == -1:
        return ""
    return xml[start + len(tag) + 2 : end]
