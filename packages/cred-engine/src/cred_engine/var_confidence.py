"""Confidence scoring for pipeline variable credentials.

Computes a 0-100 confidence score based on six factors:
  1. pattern_match  (10-40 pts)  — value regex vs name hint
  2. entropy        (-10 to +25) — Shannon entropy of the value
  3. value_length   (-5 to +10)  — credential-typical length
  4. placeholder    (-25 to -30) — known dummy / example values
  5. source_context (+5 to +10)  — variable group vs pipeline variable
  6. type_specificity (+10)      — types with distinctive prefixes
"""

from __future__ import annotations

from typing import Any

from cred_engine.entropy import shannon_entropy
from cred_engine.var_models import CredentialTarget, CredentialType

_PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "changeme",
    "change_me",
    "todo",
    "fixme",
    "replace_me",
    "replaceme",
    "your_password",
    "your-password",
    "yourpassword",
    "password123",
    "password",
    "p@ssw0rd",
    "p@ssword",
    "secret",
    "xxx",
    "xxxx",
    "xxxxxxxx",
    "dummy",
    "fake",
    "test",
    "testing",
    "example",
    "sample",
    "placeholder",
    "devstoreaccount1",
    "eby8vdm02xnohiexamplekey==",
    "notarealsecret",
    "insert_here",
    "none",
    "null",
    "n/a",
    "tbd",
    "default",
})

_PLACEHOLDER_FRAGMENTS: frozenset[str] = frozenset({
    "contoso",
    "fabrikam",
    "northwind",
    "adventureworks",
    "wideworldimporters",
})

_VALUE_PATTERN_TYPES: frozenset[CredentialType] = frozenset({
    CredentialType.AWS_ACCESS_KEY,
    CredentialType.GITHUB_PAT,
    CredentialType.GITHUB_APP_TOKEN,
    CredentialType.SLACK_TOKEN,
    CredentialType.SENDGRID_KEY,
    CredentialType.NPM_TOKEN,
    CredentialType.JWT,
    CredentialType.AZURE_STORAGE_KEY,
    CredentialType.AZURE_SAS_TOKEN,
    CredentialType.SQL_CONNECTION_STRING,
    CredentialType.AZURE_CONNECTION_STRING,
})

_HIGH_SPECIFICITY_TYPES: frozenset[CredentialType] = frozenset({
    CredentialType.AWS_ACCESS_KEY,
    CredentialType.GITHUB_PAT,
    CredentialType.GITHUB_APP_TOKEN,
    CredentialType.SENDGRID_KEY,
    CredentialType.NPM_TOKEN,
})


def score_target(target: CredentialTarget) -> tuple[float, str, list[dict[str, Any]]]:
    """Score a credential target's likelihood of being a real credential.

    Returns (score 0-100, label, list of signal dicts with factor/score/reason).
    """
    signals: list[dict[str, Any]] = []
    score = 0.0

    # 1. Pattern match method: value regex vs name hint
    ctype = target.credential_type.value
    if target.credential_type in _VALUE_PATTERN_TYPES:
        pts = 40.0
        signals.append({
            "factor": "pattern_match", "score": pts,
            "reason": f"Value matches {ctype} pattern",
        })
        score += pts
    elif target.credential_type in (CredentialType.GENERIC_PASSWORD, CredentialType.GENERIC_TOKEN):
        pts = 10.0
        signals.append({
            "factor": "pattern_match", "score": pts,
            "reason": "Matched by variable name hint only",
        })
        score += pts
    elif target.credential_type != CredentialType.UNKNOWN:
        pts = 20.0
        signals.append({
            "factor": "pattern_match", "score": pts,
            "reason": f"Value matches {ctype} pattern",
        })
        score += pts

    # 2. Shannon entropy
    if target.value:
        entropy = shannon_entropy(target.value)
        if entropy >= 4.0:
            pts = 25.0
            reason = f"High entropy ({entropy:.1f} bits/char)"
        elif entropy >= 3.0:
            pts = 15.0
            reason = f"Moderate entropy ({entropy:.1f} bits/char)"
        elif entropy >= 2.0:
            pts = 5.0
            reason = f"Low entropy ({entropy:.1f} bits/char)"
        else:
            pts = -10.0
            reason = f"Very low entropy ({entropy:.1f} bits/char)"
        signals.append({"factor": "entropy", "score": pts, "reason": reason})
        score += pts

    # 3. Value length
    val_len = len(target.value)
    if val_len >= 20:
        pts = 10.0
        signals.append({
            "factor": "value_length", "score": pts,
            "reason": f"Standard credential length ({val_len} chars)",
        })
        score += pts
    elif val_len >= 8:
        pts = 5.0
        signals.append({"factor": "value_length", "score": pts, "reason": f"Moderate length ({val_len} chars)"})
        score += pts
    elif val_len > 0:
        pts = -5.0
        signals.append({"factor": "value_length", "score": pts, "reason": f"Very short value ({val_len} chars)"})
        score += pts

    # 4. Placeholder detection
    if target.value:
        lower_val = target.value.strip().lower()
        if lower_val in _PLACEHOLDER_VALUES:
            pts = -30.0
            signals.append({"factor": "placeholder", "score": pts, "reason": f"Known placeholder value: {lower_val}"})
            score += pts
        elif any(frag in lower_val for frag in _PLACEHOLDER_FRAGMENTS):
            pts = -25.0
            matched = next(f for f in _PLACEHOLDER_FRAGMENTS if f in lower_val)
            signals.append({"factor": "placeholder", "score": pts, "reason": f"Contains placeholder name: {matched}"})
            score += pts

    # 5. Source context
    if target.source_group:
        pts = 10.0
        signals.append({"factor": "source_context", "score": pts, "reason": "Variable group (shared across pipelines)"})
        score += pts
    elif target.source_pipeline:
        pts = 5.0
        signals.append({"factor": "source_context", "score": pts, "reason": "Pipeline variable"})
        score += pts

    # 6. Type specificity
    if target.credential_type in _HIGH_SPECIFICITY_TYPES:
        pts = 10.0
        signals.append({
            "factor": "type_specificity", "score": pts,
            "reason": f"{ctype} has a distinctive prefix",
        })
        score += pts

    score = max(0.0, min(100.0, score))
    label = _score_to_label(score)
    return score, label, signals


def _score_to_label(score: float) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "likely-fp"
