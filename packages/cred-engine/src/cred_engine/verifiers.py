"""Active credential verification — read-only checks against live services.

Each verifier makes a single read-only API call to determine if a
credential is valid, invalid, or expired. No state-changing calls.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_TIMEOUT = 8


@dataclass(frozen=True, slots=True)
class VerifyResult:
    status: str  # valid | invalid | expired | error | skipped
    detail: str
    grants: str = ""


_VerifierFn = Callable[[str, dict[str, Any]], VerifyResult]


def verify_credential(
    pattern_name: str,
    secret: str,
    evidence: dict[str, Any],
) -> VerifyResult:
    """Dispatch to pattern-specific verifier. Returns a VerifyResult."""
    fn = _VERIFIERS.get(pattern_name)
    if not fn:
        return VerifyResult("skipped", f"No verifier for {pattern_name}")
    try:
        return fn(secret, evidence)
    except Exception as exc:
        logger.debug("verify %s failed: %s", pattern_name, exc)
        return VerifyResult("error", str(exc)[:200])


def _http_get(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:  # noqa: S310
            body = resp.read(8192)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, body
    except urllib.error.HTTPError as exc:
        body = exc.read(4096) if exc.fp else b""
        return exc.code, {}, body


def _verify_github_pat(secret: str, _evidence: dict[str, Any]) -> VerifyResult:
    status, headers, body = _http_get(
        "https://api.github.com/user",
        {"Authorization": f"token {secret}", "User-Agent": "cred-engine-verify"},
    )
    if status == 200:
        data = json.loads(body)
        login = data.get("login", "?")
        scopes = headers.get("x-oauth-scopes", "none")
        return VerifyResult("valid", f"Authenticated as {login}", f"Scopes: {scopes}")
    if status == 401:
        return VerifyResult("invalid", "Token rejected (401)")
    return VerifyResult("error", f"Unexpected status {status}")


def _verify_slack_token(secret: str, _evidence: dict[str, Any]) -> VerifyResult:
    status, _, body = _http_get(
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {secret}"},
    )
    if status == 200:
        data = json.loads(body)
        if data.get("ok"):
            team = data.get("team", "?")
            user = data.get("user", "?")
            return VerifyResult("valid", f"Authenticated as {user} in {team}", f"Team: {team}")
        error = data.get("error", "unknown")
        if error in ("invalid_auth", "token_revoked", "account_inactive"):
            return VerifyResult("invalid", f"Token invalid: {error}")
        return VerifyResult("error", f"Slack API error: {error}")
    return VerifyResult("error", f"Unexpected status {status}")


def _verify_sendgrid(secret: str, _evidence: dict[str, Any]) -> VerifyResult:
    status, _, body = _http_get(
        "https://api.sendgrid.com/v3/scopes",
        {"Authorization": f"Bearer {secret}"},
    )
    if status == 200:
        data = json.loads(body)
        scopes = data.get("scopes", [])
        return VerifyResult("valid", f"Key valid, {len(scopes)} scope(s)", f"Scopes: {', '.join(scopes[:5])}")
    if status in (401, 403):
        return VerifyResult("invalid", f"Key rejected ({status})")
    return VerifyResult("error", f"Unexpected status {status}")


def _verify_stripe(secret: str, _evidence: dict[str, Any]) -> VerifyResult:
    creds = base64.b64encode(f"{secret}:".encode()).decode()
    status, _, body = _http_get(
        "https://api.stripe.com/v1/balance",
        {"Authorization": f"Basic {creds}"},
    )
    if status == 200:
        env = "live" if "sk_live_" in secret else "test"
        return VerifyResult("valid", f"Stripe key valid ({env} mode)", "Full API access")
    if status in (401, 403):
        return VerifyResult("invalid", f"Key rejected ({status})")
    return VerifyResult("error", f"Unexpected status {status}")


def _verify_npm_token(secret: str, _evidence: dict[str, Any]) -> VerifyResult:
    status, _, body = _http_get(
        "https://registry.npmjs.org/-/whoami",
        {"Authorization": f"Bearer {secret}"},
    )
    if status == 200:
        data = json.loads(body)
        username = data.get("username", "?")
        return VerifyResult("valid", f"NPM token for {username}", "Package registry access")
    if status in (401, 403):
        return VerifyResult("invalid", f"Token rejected ({status})")
    return VerifyResult("error", f"Unexpected status {status}")


def _verify_twilio(secret: str, evidence: dict[str, Any]) -> VerifyResult:
    file_content = evidence.get("_file_content", "")
    sid_match = re.search(r"(AC[0-9a-fA-F]{32})", file_content) if file_content else None
    if not sid_match:
        return VerifyResult("skipped", "Need AccountSid to verify (not found in context)")
    sid = sid_match.group(1)
    creds = base64.b64encode(f"{sid}:{secret}".encode()).decode()
    status, _, body = _http_get(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
        {"Authorization": f"Basic {creds}"},
    )
    if status == 200:
        data = json.loads(body)
        name = data.get("friendly_name", "?")
        return VerifyResult("valid", f"Twilio account: {name}", "SMS/voice/video API access")
    if status in (401, 403):
        return VerifyResult("invalid", f"Auth rejected ({status})")
    return VerifyResult("error", f"Unexpected status {status}")


def _verify_jwt(secret: str, _evidence: dict[str, Any]) -> VerifyResult:
    """Decode JWT and check expiry — no network call needed."""
    import time

    parts = secret.split(".")
    if len(parts) != 3:
        return VerifyResult("error", "Not a valid JWT format")

    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return VerifyResult("error", "Could not decode JWT payload")

    exp = payload.get("exp")
    if exp is None:
        sub = payload.get("sub", "?")
        iss = payload.get("iss", "?")
        return VerifyResult("valid", f"JWT has no expiry (sub={sub}, iss={iss})", f"Issuer: {iss}")

    now = time.time()
    if exp < now:
        return VerifyResult("expired", f"JWT expired at {time.ctime(exp)}")

    sub = payload.get("sub", "?")
    iss = payload.get("iss", "?")
    remaining_h = round((exp - now) / 3600, 1)
    return VerifyResult("valid", f"JWT valid for {remaining_h}h (sub={sub})", f"Issuer: {iss}")


def _verify_azure_storage(secret: str, evidence: dict[str, Any]) -> VerifyResult:
    """Check Azure Storage key by attempting to list containers via REST."""
    import datetime
    import hashlib
    import hmac

    file_content = evidence.get("_file_content", "")
    acct_match = re.search(r"(?i)AccountName\s*=\s*([a-z0-9]{3,24})", file_content) if file_content else None
    if not acct_match:
        return VerifyResult("skipped", "Need AccountName to verify (not found in context)")

    account = acct_match.group(1)
    now = datetime.datetime.now(datetime.UTC)
    date_str = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
    version = "2020-10-02"

    string_to_sign = (
        f"GET\n\n\n\n\n\n\n\n\n\n\n\n"
        f"x-ms-date:{date_str}\nx-ms-version:{version}\n"
        f"/{account}/\ncomp:list"
    )
    try:
        key_bytes = base64.b64decode(secret)
    except Exception:
        return VerifyResult("error", "Could not decode storage key (not valid base64)")
    sig = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode()
    auth = f"SharedKey {account}:{sig}"

    status, _, body = _http_get(
        f"https://{account}.blob.core.windows.net/?comp=list",
        {
            "x-ms-date": date_str,
            "x-ms-version": version,
            "Authorization": auth,
        },
    )
    if status == 200:
        return VerifyResult("valid", f"Storage key valid for {account}", "Full blob/table/queue/file access")
    if status == 403:
        return VerifyResult("invalid", f"Key rejected for {account} (403)")
    if status == 404:
        return VerifyResult("error", f"Account {account} not found")
    return VerifyResult("error", f"Unexpected status {status}")


_VERIFIERS: dict[str, _VerifierFn] = {
    "GitHub PAT / App Token": _verify_github_pat,
    "Slack Token": _verify_slack_token,
    "SendGrid API Key": _verify_sendgrid,
    "Stripe Secret Key": _verify_stripe,
    "NuGet / NPM Auth Token": _verify_npm_token,
    "Twilio Auth": _verify_twilio,
    "Bearer / JWT Token": _verify_jwt,
    "Azure Storage / Cosmos Key": _verify_azure_storage,
}
