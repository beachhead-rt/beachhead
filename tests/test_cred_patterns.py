"""Tests for cred-engine-backed credential detection patterns."""

from __future__ import annotations

from cred_engine.patterns import PATTERNS as CE_PATTERNS

from beachhead.core.cred_bridge import scan_text
from beachhead.modules.harvest.cred_patterns import (
    SCAN_QUERIES,
    looks_like_credential,
)


def test_cred_engine_patterns_non_empty() -> None:
    assert len(CE_PATTERNS) >= 30


def test_scan_queries_non_empty() -> None:
    assert len(SCAN_QUERIES) >= 5


def test_scan_query_ids_unique() -> None:
    ids = [q.id for q in SCAN_QUERIES]
    assert len(ids) == len(set(ids))


def test_every_scan_query_has_pattern_names() -> None:
    for q in SCAN_QUERIES:
        assert q.pattern_names, f"ScanQuery {q.id} has no pattern names"
        assert q.search_text, f"ScanQuery {q.id} has empty search text"


def test_looks_like_credential_positive() -> None:
    assert looks_like_credential("password=s3cretP@ssw0rd123")
    assert looks_like_credential("AccountKey=abcdefghij12345678")
    assert looks_like_credential("Authorization: Bearer eyJhbGciOiJSUzI1NiI")


def test_looks_like_credential_negative() -> None:
    assert not looks_like_credential("just some normal text")
    assert not looks_like_credential("password without a value part")
    assert not looks_like_credential("")


# --- cred-engine scan_text integration ---

def test_scan_text_detects_azure_storage() -> None:
    content = (
        "DefaultEndpointsProtocol=https;AccountName=foo;"
        "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==;"
        "EndpointSuffix=core.windows.net"
    )
    matches = scan_text(content, file_path="config.json")
    assert len(matches) >= 1
    patterns_found = {m["pattern"] for m in matches}
    assert any("storage" in p.lower() or "azure" in p.lower() for p in patterns_found)


def test_scan_text_detects_aws_key() -> None:
    matches = scan_text("AKIAJ5ZVAB7DEADBEEF3", file_path="env.sh")
    patterns_found = {m["pattern"] for m in matches}
    assert any("aws" in p.lower() for p in patterns_found)


def test_scan_text_detects_github_pat() -> None:
    matches = scan_text(
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        file_path="config.yml",
    )
    assert len(matches) >= 1


def test_scan_text_detects_private_key() -> None:
    content = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWHF9x7Q3l\n"
        "-----END RSA PRIVATE KEY-----"
    )
    matches = scan_text(content, file_path="key.pem")
    assert len(matches) >= 1


def test_scan_text_returns_empty_for_clean() -> None:
    matches = scan_text("just regular code with no secrets", file_path="app.py")
    assert matches == []


# --- New pattern coverage tests ---

def test_scan_text_detects_slack_webhook() -> None:
    content = '"slack_webhook": "https://hooks.slack.com/services/T01ABCDEF/B03MNOPQR/z9Y8x7W6v5U4t3S2r1Q0p9O8"'
    matches = scan_text(content, file_path="config.json", skip_filters=True)
    assert any(m["pattern"] == "Slack Webhook URL" for m in matches)


def test_scan_text_detects_teams_webhook() -> None:
    content = 'teams_webhook: "https://BB247.webhook.office.com/webhookb2/a1b2c3d4-e5f6-7890-abcd-ef1234567890/IncomingWebhook/f9e8d7c6b5a4938271605040/a1b2c3d4-e5f6-7890-abcd-ef1234567890"'
    matches = scan_text(content, file_path="settings.yml", skip_filters=True)
    assert any(m["pattern"] == "Teams / Office 365 Webhook URL" for m in matches)


def test_scan_text_detects_launchdarkly_sdk_key() -> None:
    content = "const LAUNCHDARKLY_SDK_KEY = 'sdk-b4a7c2e1-9f38-4d5a-8c6b-3456789abcde';"
    matches = scan_text(content, file_path="flags.js", skip_filters=True)
    assert any(m["pattern"] == "LaunchDarkly SDK Key" for m in matches)


def test_scan_text_detects_sendgrid_api_key() -> None:
    content = '"sendgrid_api_key": "SG.a1b2c3d4e5f6.g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"'
    matches = scan_text(content, file_path="config.json", skip_filters=True)
    assert any(m["pattern"] == "SendGrid API Key" for m in matches)


def test_scan_text_detects_statuspage_key() -> None:
    content = '"api_key": "stpg-k9x2m4v7b1n8f3j6w0q5y8r2t4p7s1a3"'
    matches = scan_text(content, file_path="endpoints.json", skip_filters=True)
    assert any(m["pattern"] == "StatusPage API Key" for m in matches)


def test_scan_text_detects_pagerduty_key() -> None:
    content = '"pagerduty_key": "e8f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5"'
    matches = scan_text(content, file_path="config.json", skip_filters=True)
    assert any(m["pattern"] == "PagerDuty Integration Key" for m in matches)


def test_scan_text_detects_opsgenie_key() -> None:
    content = '"opsgenie_api_key": "f1e2d3c4-b5a6-7890-fedc-ba9876543210"'
    matches = scan_text(content, file_path="targets.json", skip_filters=True)
    assert any(m["pattern"] == "OpsGenie API Key" for m in matches)


def test_scan_text_detects_amqp_url_creds() -> None:
    content = '"url": "amqp://notif_svc:R@bb1tMQ!Pr0d#2025@rabbitmq-prod.internal:5672/notifications"'
    matches = scan_text(content, file_path="config.json", skip_filters=True)
    assert any(m["pattern"] == "Protocol URL with Embedded Credentials" for m in matches)
    raw = next(m for m in matches if m["pattern"] == "Protocol URL with Embedded Credentials")
    assert raw["_raw_secret"] == "R@bb1tMQ!Pr0d#2025"


def test_scan_text_detects_base64_credential() -> None:
    content = '"pass_b64": "TjB0MWZpY0B0aTBuJFMzcnYxYzMhMjAyNQ=="'
    matches = scan_text(content, file_path="config.json", skip_filters=True)
    assert any(m["pattern"] == "Base64-Encoded Credential" for m in matches)


def test_scan_text_detects_aws_secret_key_in_dict() -> None:
    content = '"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    matches = scan_text(content, file_path="config.py", skip_filters=True)
    assert any("aws" in m["pattern"].lower() for m in matches)
