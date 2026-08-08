"""Bridge between cred-engine and Beachhead's store/secrets layer.

Delegates all credential detection, scoring, entropy checks, and verification
to the ``cred-engine`` library while writing results through Beachhead's
own store and secret store.  Modules call the helpers here instead of
reimplementing pattern matching.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from cred_engine.patterns import PATTERNS as CE_PATTERNS
from cred_engine.pipeline import scan_content as ce_scan_content
from cred_engine.var_classifier import classify as ce_classify
from cred_engine.var_confidence import score_target as ce_score_target
from cred_engine.var_models import CredentialTarget, CredentialType

if TYPE_CHECKING:
    from beachhead.core.module import RunContext

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_SECURE_STRING_RE = re.compile(
    r"ConvertTo-SecureString\s+[\"']([^\"']+)[\"']", re.IGNORECASE,
)

_EXTRA_DETAIL_KEYS = (
    "pipeline_id", "pipeline_name", "group_name",
    "group_id", "wiki_name", "page_path",
    "build_id", "build_number", "pr_id",
)


def scan_text(
    content: str,
    *,
    file_path: str = "",
    branch: str = "main",
    repo: str = "",
    skip_filters: bool = False,
    find_all: bool = False,
) -> list[dict[str, Any]]:
    """Scan raw text for credentials using cred-engine's full pattern set.

    Returns a list of match dicts (pattern name, confidence, entropy,
    redacted preview, extracted secret).  No persistence — the caller
    decides what to store.
    """
    return ce_scan_content(
        file_path, content, branch=branch, repo=repo,
        skip_filters=skip_filters, find_all=find_all,
    )


def scan_and_record(
    ctx: RunContext,
    content: str,
    *,
    file_path: str,
    branch: str = "main",
    repo: str = "",
    project: str = "",
    org: str = "",
    url: str = "",
    finding_kind: str,
    source_module: str,
    resource_id: str = "",
    extra_details: dict[str, Any] | None = None,
    skip_filters: bool = False,
    find_all: bool = False,
) -> int:
    """Scan text content and write findings to Beachhead's stores.

    Uses cred-engine for detection, scoring, and entropy checks, then
    writes to ``ctx.store`` (redacted) and ``ctx.secrets`` (plaintext).
    Returns the number of findings recorded.
    """
    matches = ce_scan_content(
        file_path, content, branch=branch, repo=repo,
        skip_filters=skip_filters, find_all=find_all,
    )
    resolved_resource = resource_id or (f"ado://{org}/{project}/{repo}" if org else repo)
    seen_values: set[str] = set()
    count = 0

    for match in matches:
        pattern_name = match.get("pattern", "unknown")
        confidence = match.get("confidence", "medium")

        raw_secret = match.get("_raw_secret") or ""
        if not raw_secret and match.get("secret_preview"):
            raw_secret = _extract_secret(content, pattern_name)

        if raw_secret and raw_secret in seen_values:
            continue
        if raw_secret:
            seen_values.add(raw_secret)

        ref = f"{pattern_name} in {repo}/{file_path}" if repo else f"{pattern_name} in {file_path}"
        if match.get("secret_preview"):
            ref = f"[{confidence}] {ref}"

        _record_match(
            ctx,
            match=match,
            raw_secret=raw_secret,
            finding_kind=finding_kind,
            source_module=source_module,
            resource_id=resolved_resource,
            reference=ref,
            url=url,
            org=org,
            project=project,
            repo=repo,
            file_path=file_path,
            branch=branch,
            extra_details=extra_details,
        )
        count += 1

    return count


def _extract_secret(content: str, pattern_name: str) -> str:
    """Re-extract the raw secret value from content using cred-engine's pattern."""
    for p in CE_PATTERNS:
        if p.name == pattern_name and p.secret_regex:
            m = re.search(p.secret_regex, content)
            if m:
                secret = m.group(1) if m.lastindex else m.group(0)
                if secret and "convertto-securestring" in secret.lower():
                    cs = _SECURE_STRING_RE.search(content)
                    if cs:
                        return cs.group(1)
                return secret
    return ""


def _record_match(
    ctx: RunContext,
    *,
    match: dict[str, Any],
    raw_secret: str,
    finding_kind: str,
    source_module: str,
    resource_id: str,
    reference: str,
    url: str,
    org: str,
    project: str,
    repo: str,
    file_path: str,
    branch: str,
    extra_details: dict[str, Any] | None,
) -> None:
    """Persist one match to the main store and (optionally) the secret store."""
    pattern_name = match.get("pattern", "unknown")

    details: dict[str, Any] = {
        "pattern_name": pattern_name,
        "confidence": match.get("confidence", "medium"),
        "confidence_score": match.get("confidence_score", 0),
        "file_path": file_path,
        "branch": branch,
        "repo_name": repo,
        "project": project,
        "org": org,
    }
    if match.get("entropy") is not None:
        details["entropy"] = match["entropy"]
    if match.get("reasons"):
        details["fp_reasons"] = match["reasons"]
    if url:
        details["ado_url"] = url
    if extra_details:
        details.update(extra_details)

    ctx.store.insert_finding(
        kind=finding_kind,
        resource_id=resource_id,
        reference=reference,
        run_id=ctx.run_id,
        redacted=True,
        details=details,
    )

    store_value = raw_secret
    if pattern_name == "Inline Login Credentials":
        match_text = match.get("_match_text", "")
        if match_text and " / " in match_text:
            before_slash = match_text.rsplit(" / ", 1)[0]
            words = before_slash.split()
            username = words[-1].strip("`*_") if words else ""
            if username:
                store_value = f"{username} / {raw_secret}"

    if ctx.secrets is not None and raw_secret:
        cred_details: dict[str, Any] = {
            "source_module": source_module,
            "credential_type": pattern_name,
            "context": f"{repo}:{file_path}" if repo else file_path,
            "org": org,
            "project": project,
        }
        if repo:
            cred_details["repo_name"] = repo
        if file_path:
            cred_details["file_path"] = file_path
        if extra_details:
            for k in _EXTRA_DETAIL_KEYS:
                if k in extra_details:
                    cred_details[k] = extra_details[k]
        ctx.secrets.store_credential(
            kind=finding_kind,
            resource_id=resource_id,
            reference=reference,
            run_id=ctx.run_id,
            value=store_value,
            details=cred_details,
        )


def scan_snippet(
    snippet: str,
    *,
    repo: str = "",
    file_path: str = "",
    branch: str = "main",
    skip_filters: bool = False,
    find_all: bool = False,
) -> list[dict[str, Any]]:
    """Scan an ADO search snippet (HTML stripped) against cred-engine patterns.

    Returns match dicts like scan_text but strips HTML first.
    """
    clean = _HTML_TAG_RE.sub("", snippet)
    if not clean.strip():
        return []
    return ce_scan_content(
        file_path, clean, branch=branch, repo=repo,
        skip_filters=skip_filters, find_all=find_all,
    )


def record_snippet_matches(
    ctx: RunContext,
    matches: list[dict[str, Any]],
    raw_text: str,
    *,
    finding_kind: str,
    source_module: str,
    resource_id: str,
    url: str = "",
    org: str = "",
    project: str = "",
    repo: str = "",
    file_path: str = "",
    branch: str = "",
    extra_details: dict[str, Any] | None = None,
) -> int:
    """Record pre-computed matches to Beachhead's stores.

    Use when the caller already called ``scan_snippet`` or ``scan_text``
    and wants to persist the results.
    """
    seen_values: set[str] = set()
    count = 0
    for match in matches:
        pattern_name = match.get("pattern", "unknown")
        confidence = match.get("confidence", "medium")

        raw = match.get("_raw_secret") or ""
        if not raw and match.get("secret_preview"):
            raw = _extract_secret(raw_text, pattern_name)

        if raw and raw in seen_values:
            continue
        if raw:
            seen_values.add(raw)

        ref_file = f"{repo}/{file_path}" if repo else file_path
        ref = f"[{confidence}] {pattern_name} in {ref_file}"

        _record_match(
            ctx,
            match=match,
            raw_secret=raw,
            finding_kind=finding_kind,
            source_module=source_module,
            resource_id=resource_id,
            reference=ref,
            url=url,
            org=org,
            project=project,
            repo=repo,
            file_path=file_path,
            branch=branch,
            extra_details=extra_details,
        )
        count += 1
    return count


def classify_variable(
    ctx: RunContext,
    *,
    variable_name: str,
    value: str,
    resource: str,
    project: str = "",
    org: str = "",
    source_pipeline: str = "",
    source_group: str = "",
    finding_kind: str = "ado_pipeline_variable_credential",
    source_module: str = "harvest.ado_variable_scan",
    min_confidence: float = 10.0,
) -> bool:
    """Classify a pipeline variable and record if it looks like a credential.

    Uses cred-engine's variable classifier and confidence scorer.
    Returns True if a finding was recorded.
    """
    cred_type = ce_classify(value, variable_name)
    if cred_type == CredentialType.UNKNOWN:
        return False

    target = CredentialTarget(
        check_id=f"CRED-{cred_type.value.upper()}",
        variable_name=variable_name,
        resource=resource,
        value=value,
        credential_type=cred_type,
        source_pipeline=source_pipeline,
        source_group=source_group,
        project=project,
    )

    conf_score, conf_label, signals = ce_score_target(target)
    if conf_score < min_confidence:
        return False

    source = source_pipeline or source_group or resource

    details: dict[str, Any] = {
        "credential_type": cred_type.value,
        "variable_name": variable_name,
        "confidence": conf_label,
        "confidence_score": conf_score,
        "confidence_signals": signals,
        "redacted_value": target.redacted_value,
        "org": org,
        "project": project,
    }
    if source_pipeline:
        details["pipeline_name"] = source_pipeline
    elif source_group:
        details["group_name"] = source_group

    resource_id = f"ado://{org}/{project}/{source}" if org else f"{project}/{source}"

    ctx.store.insert_finding(
        kind=finding_kind,
        resource_id=resource_id,
        reference=f"[{conf_label}] {cred_type.value}: {variable_name} in {source}",
        run_id=ctx.run_id,
        redacted=True,
        details=details,
    )

    if ctx.secrets is not None:
        cred_details: dict[str, Any] = {
            "source_module": source_module,
            "credential_type": cred_type.value,
            "context": f"Variable '{variable_name}' in {source}",
            "variable_name": variable_name,
            "org": org,
            "project": project,
        }
        if source_pipeline:
            cred_details["pipeline_name"] = source_pipeline
        if source_group:
            cred_details["group_name"] = source_group
        ctx.secrets.store_credential(
            kind=finding_kind,
            resource_id=resource_id,
            reference=f"[{conf_label}] {cred_type.value}: {variable_name} in {source}",
            run_id=ctx.run_id,
            value=value,
            details=cred_details,
        )

    return True
