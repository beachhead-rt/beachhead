"""Confidence scoring for credential findings.

Assigns a signed integer score based on file path, branch, severity, and
pattern-specific signals. Higher scores = more likely a real credential.
"""

from __future__ import annotations

import re

from cred_engine.models import Severity

# ---------------------------------------------------------------------------
# Path / filename classification regexes
# ---------------------------------------------------------------------------

_TEST_PATH_RE = re.compile(
    r"(?i)(^|/)(tests?|spec|fixtures?|testdata|mocks?|__tests__|"
    r"examples?|samples?|demos?|templates?|scaffolds?|docs?|wiki)(/|$)"
)
_TEST_FILENAME_RE = re.compile(r"(?i)(test|example|sample|mock|demo|dummy|template|fixture)")
_DOC_EXT_RE = re.compile(r"\.(md|txt|rst|adoc)$", re.IGNORECASE)
_CONFIG_EXT_RE = re.compile(r"\.(config|json|xml|yaml|yml|env|properties|ini)$", re.IGNORECASE)
_PROD_FILE_RE = re.compile(r"(?i)(web\.config|appsettings|connectionstrings|app\.config)", re.IGNORECASE)
_VENDORED_PATH_RE = re.compile(
    r"(?i)(^|/)(node_modules|vcpkg|vendor|third[_-]?party|packages|\.nuget)(/|$)"
)
_PRIVATE_KEY_PATTERNS = frozenset({"PEM / RSA / SSH Private Key"})
_DKIM_PATH_RE = re.compile(r"(?i)(^|/)(pki|dkim|prodops-dkim|mail[_-]?signing)(/|$)")

FAKE_NAME_WORDS = frozenset(
    {
        "fake",
        "test",
        "dummy",
        "example",
        "sample",
        "placeholder",
        "mock",
        "demo",
        "sandbox",
        "myaccount",
        "youraccount",
        "yourname",
        "contoso",
        "fabrikam",
        "northwind",
        "adventureworks",
        "wideworldimporters",
        "localhost",
        "devstoreaccount1",
    }
)

KNOWN_FAKE_VALUES = frozenset(
    {
        "akiaiosfodnn7example",
        "akiai44qh8dhbexample",
        "wjalrxutnfemi",
        "devstoreaccount1",
        "eby8vdm02xnocq",
        "password123",
        "p@ssw0rd",
        "p@ssword1",
        "changeme",
        "sk_test_",
        "pk_test_",
        "acxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghp_example",
        "ghp_xxxx",
        "ghp_0000000000000000000000000000000000000",
        "xoxb-not-a-real-token",
        "sg.notarealkey",
        "notarealsecret",
        "replace_me_with_real_value",
        "contoso",
        "fabrikam",
        "northwind",
        "adventureworks",
        "wideworldimporters",
        "django-insecure-",
    }
)


def score_finding(
    file_path: str,
    branch: str,
    severity: Severity,
    pattern_name: str = "",
) -> tuple[int, list[str]]:
    """Score a finding's likelihood of being a real credential.

    Returns (score, reasons). Higher = more likely real.
    Negative = likely false positive.
    """
    score = 0
    reasons: list[str] = []

    # --- Negative signals (likely false positive) ---
    if _TEST_PATH_RE.search(file_path):
        score -= 40
        reasons.append("test/example directory")
    filename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    if _TEST_FILENAME_RE.search(filename):
        score -= 30
        reasons.append("test/example filename")
    if _DOC_EXT_RE.search(file_path):
        score -= 20
        reasons.append("documentation file")
    if _VENDORED_PATH_RE.search(file_path):
        score -= 35
        reasons.append("vendored/third-party path")

    path_lower = file_path.lower()
    for word in FAKE_NAME_WORDS:
        if word in path_lower:
            score -= 25
            reasons.append(f"'{word}' in path")
            break

    # --- Positive signals (likely real) ---
    if _CONFIG_EXT_RE.search(file_path):
        score += 10
    if _PROD_FILE_RE.search(file_path):
        score += 30
        reasons.append("production config file")
    if branch in ("main", "master") or branch.startswith("release"):
        score += 10
    elif branch.startswith(("feature", "dev", "test")):
        score -= 5
    if severity == Severity.CRITICAL:
        score += 15

    # --- Pattern-specific path signals ---
    if pattern_name in _PRIVATE_KEY_PATTERNS and _DKIM_PATH_RE.search(file_path):
        score += 40
        reasons.append("DKIM/PKI path — likely real signing key")

    return score, reasons


def confidence_label(score: int) -> str:
    """Map a numeric confidence score to a human-readable label."""
    if score >= 30:
        return "high"
    if score >= 0:
        return "medium"
    if score >= -20:
        return "low"
    return "likely-fp"
