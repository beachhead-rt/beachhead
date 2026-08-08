"""Scanning pipeline — wires patterns, scoring, entropy, and persistence.

This module contains the core scan logic that is platform-agnostic.
Callers provide a search adapter (see search.py for the protocol) and
this module handles scoring, entropy validation, fake detection,
optional verification, and persistence.

Two entry points:
- process_hit(): score and persist a single search result
- scan_content(): scan raw file content against all patterns (no search API)
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from cred_engine.allowlist import is_suppressed
from cred_engine.entropy import check_entropy, shannon_entropy
from cred_engine.models import FindingStatus, ToolSource, UnifiedFinding, redact_value
from cred_engine.patterns import PATTERNS, CredPattern
from cred_engine.scorer import KNOWN_FAKE_VALUES, confidence_label, score_finding
from cred_engine.store import FindingsStore
from cred_engine.verifiers import verify_credential

logger = logging.getLogger(__name__)

_CODE_REF_RE = re.compile(
    r"^(?:"
    r"(?:var|env|process\.env|os\.environ)\."
    r"|[A-Z_]{2,}\["
    r"|(?:Get|Set|New|Remove|ConvertTo)-[A-Za-z]+"
    r"|\$"
    r"|%[A-Z_]+%"
    r"|[0-9]*>/?(?:dev/)?null"
    r")",
    re.IGNORECASE,
)
_SECURE_STRING_RE = re.compile(
    r"ConvertTo-SecureString\s+[\"']([^\"']+)[\"']", re.IGNORECASE,
)




def process_hit(
    *,
    repo: str,
    file_path: str,
    branch: str,
    content: str,
    url: str,
    project: str,
    pattern: CredPattern,
    store: FindingsStore,
    run_id: str,
    verify: bool = False,
    allowlist_entries: list[dict[str, str]] | None = None,
    store_secrets: bool = False,
) -> UnifiedFinding | None:
    """Score, validate, and persist a single credential search hit.

    Returns the UnifiedFinding if persisted, or None if discarded.
    When store_secrets is True, the raw credential is saved to the database.
    """
    if allowlist_entries and is_suppressed(
        allowlist_entries, repo=repo, file_path=file_path, pattern_name=pattern.name
    ):
        return None

    # 1. Path/branch scoring
    fp_score, fp_reasons = score_finding(file_path, branch, pattern.severity, pattern.name)

    # 2. Entropy check
    entropy_val, passes, secret = check_entropy(content, pattern)
    if entropy_val is not None:
        if passes:
            fp_score += 15
            fp_reasons.append(f"entropy {entropy_val:.1f} >= {pattern.min_entropy}")
        else:
            fp_score -= 30
            fp_reasons.append(f"entropy {entropy_val:.1f} < {pattern.min_entropy}")

    # 3. Known fake detection
    if secret:
        lower = secret.lower()
        for fake in KNOWN_FAKE_VALUES:
            if fake in lower:
                fp_score -= 50
                fp_reasons.append(f"known fake: {fake}")
                break

    # 4. Early discard
    if not passes and fp_score < -40:
        logger.debug("discarding %s in %s/%s (score=%d)", pattern.name, repo, file_path, fp_score)
        return None

    # 5. Build evidence
    evidence: dict[str, Any] = {
        "pattern": pattern.name,
        "file_path": file_path,
        "branch": branch,
        "repo": repo,
    }
    if entropy_val is not None:
        evidence["entropy"] = round(entropy_val, 2)
        evidence["entropy_threshold"] = pattern.min_entropy
        evidence["entropy_pass"] = passes
    if secret:
        evidence["redacted_value"] = redact_value(secret)

    # 6. Optional verification
    confidence = confidence_label(fp_score)
    verification_meta: dict[str, Any] = {}
    if verify and secret:
        result = verify_credential(pattern.name, secret, {**evidence, "_file_content": content})
        verification_meta["verification_status"] = result.status
        verification_meta["verification_detail"] = result.detail
        if result.grants:
            verification_meta["verification_grants"] = result.grants
        if result.status == "valid":
            fp_score += 50
            confidence = "confirmed"
        elif result.status == "invalid":
            fp_score -= 40
            confidence = confidence_label(fp_score)
        elif result.status == "expired":
            fp_score -= 20
            confidence = confidence_label(fp_score)

    # 7. Build metadata
    metadata: dict[str, Any] = {
        "confidence": confidence,
        "confidence_score": fp_score,
        "fp_reasons": fp_reasons,
    }
    if entropy_val is not None:
        metadata["entropy"] = round(entropy_val, 2)
    metadata.update(verification_meta)

    # 8. Build finding
    filename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    finding = UnifiedFinding(
        id=uuid.uuid4().hex[:8],
        tool=ToolSource.CRED_SCAN,
        check_id="REPO-CREDENTIALS",
        title=f"{pattern.name} in {repo}/{filename}",
        status=FindingStatus.FAIL,
        severity=pattern.severity,
        description=f"Potential {pattern.name} found in {file_path}. Validate and rotate if confirmed.",
        resource=f"{project}/{repo}" if project else repo,
        project=project,
        url=url,
        evidence=evidence,
        remediation="Review the credential and rotate if confirmed real.",
        commands=[],
        metadata=metadata,
    )

    # 9. Persist
    store.upsert_finding(
        finding, run_id,
        repo=repo, file_path=file_path,
        pattern_id=pattern.name, secret_value=secret or "",
        store_secret=store_secrets,
    )
    return finding


def scan_content(
    file_path: str,
    content: str,
    *,
    branch: str = "main",
    repo: str = "",
    patterns: list[CredPattern] | None = None,
    skip_filters: bool = False,
    find_all: bool = False,
) -> list[dict[str, Any]]:
    """Scan raw file content against all patterns without any persistence.

    Returns a list of match dicts — useful for local/offline scanning or
    integration into other tools where you don't need the full pipeline.

    When *skip_filters* is True, extension filtering, search-term
    pre-filtering, entropy gating, and known-fake-value checks are all
    bypassed — only the raw regex determines whether a match is reported.

    When *find_all* is True, ``finditer`` replaces ``search`` so every
    occurrence of a pattern in the content produces a match — useful for
    wiki pages or config files that contain multiple distinct credentials.
    """
    target_patterns = patterns or PATTERNS
    findings: list[dict[str, Any]] = []

    for pattern in target_patterns:
        if not skip_filters and pattern.extensions:
            ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
            if ext not in pattern.extensions:
                continue

        if not skip_filters:
            matched = False
            for term in pattern.search_terms:
                clean_term = re.sub(r"\s+ext:\S+", "", term).strip()
                if clean_term.lower() in content.lower():
                    matched = True
                    break

            if not matched:
                continue

        if pattern.secret_regex:
            if find_all:
                regex_matches = list(re.finditer(pattern.secret_regex, content))
            else:
                m = re.search(pattern.secret_regex, content)
                regex_matches = [m] if m else []
            if not regex_matches:
                continue

            for m in regex_matches:
                secret = m.group(1) if m.lastindex else m.group(0)
                if secret and _CODE_REF_RE.match(secret):
                    if "convertto-securestring" in secret.lower():
                        cs = _SECURE_STRING_RE.search(content)
                        if cs:
                            secret = cs.group(1)
                        else:
                            continue
                    else:
                        continue
                entropy_val = shannon_entropy(secret) if secret else None

                below_entropy = (
                    pattern.min_entropy and secret
                    and entropy_val is not None and entropy_val < pattern.min_entropy
                )
                if not skip_filters and below_entropy:
                    continue

                if not skip_filters and secret:
                    lower = secret.lower()
                    if any(fake in lower for fake in KNOWN_FAKE_VALUES):
                        continue

                fp_score, fp_reasons = score_finding(file_path, branch, pattern.severity, pattern.name)
                if entropy_val is not None:
                    fp_score += 15

                findings.append({
                    "pattern": pattern.name,
                    "file": file_path,
                    "severity": pattern.severity.value,
                    "confidence": confidence_label(fp_score),
                    "confidence_score": fp_score,
                    "secret_preview": redact_value(secret) if secret else None,
                    "_raw_secret": secret,
                    "_match_text": m.group(0),
                    "entropy": round(entropy_val, 2) if entropy_val is not None else None,
                    "reasons": fp_reasons,
                })
                if not skip_filters:
                    break  # one match per pattern per file
        else:
            fp_score, fp_reasons = score_finding(file_path, branch, pattern.severity, pattern.name)
            findings.append({
                "pattern": pattern.name,
                "file": file_path,
                "severity": pattern.severity.value,
                "confidence": confidence_label(fp_score),
                "confidence_score": fp_score,
                "secret_preview": None,
                "_raw_secret": None,
                "entropy": None,
                "reasons": fp_reasons,
            })
            if not skip_filters:
                break

    return findings
