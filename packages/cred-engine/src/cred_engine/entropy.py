"""Shannon entropy calculation and entropy-based credential validation."""

from __future__ import annotations

import math
import re

from cred_engine.patterns import CredPattern


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not value:
        return 0.0
    length = len(value)
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def check_entropy(
    content: str,
    pattern: CredPattern,
) -> tuple[float | None, bool, str]:
    """Extract a secret value from file content and check its entropy.

    Returns (entropy_value, passes_threshold, extracted_secret).
    If the pattern has no secret_regex or min_entropy, returns (None, True, "").
    If the regex doesn't match, returns (None, True, "") — benefit of the doubt.
    """
    if not pattern.secret_regex or pattern.min_entropy is None:
        return None, True, ""

    match = re.search(pattern.secret_regex, content)
    if not match:
        return None, True, ""

    secret = match.group(1) if match.lastindex else match.group(0)
    ent = shannon_entropy(secret)
    passes = ent >= pattern.min_entropy
    return ent, passes, secret
