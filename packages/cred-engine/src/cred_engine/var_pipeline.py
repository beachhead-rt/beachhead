"""Pipeline variable scanning — classifies and scores credential values.

This module processes raw variable data (name + value pairs from pipeline
configs, variable groups, secret stores, etc.) through the classifier and
confidence scorer, then persists findings to the store.

Two entry points:
- process_variable(): classify, score, and persist a single variable
- scan_variables(): batch-process a list of variable dicts
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from cred_engine.models import FindingStatus, Severity, ToolSource, UnifiedFinding
from cred_engine.store import FindingsStore
from cred_engine.var_classifier import classify
from cred_engine.var_confidence import score_target
from cred_engine.var_models import CredentialTarget, CredentialType, ValidationStatus

logger = logging.getLogger(__name__)

_STATUS_MAP: dict[ValidationStatus, FindingStatus] = {
    ValidationStatus.VALID: FindingStatus.FAIL,
    ValidationStatus.INVALID: FindingStatus.PASS,
    ValidationStatus.EXPIRED: FindingStatus.WARN,
    ValidationStatus.ERROR: FindingStatus.ERROR,
    ValidationStatus.SKIPPED: FindingStatus.SKIP,
    ValidationStatus.UNKNOWN: FindingStatus.UNKNOWN,
}

_SEVERITY_MAP: dict[CredentialType, Severity] = {
    CredentialType.AWS_ACCESS_KEY: Severity.CRITICAL,
    CredentialType.GITHUB_PAT: Severity.HIGH,
    CredentialType.GITHUB_APP_TOKEN: Severity.HIGH,
    CredentialType.AZURE_STORAGE_KEY: Severity.CRITICAL,
    CredentialType.AZURE_SAS_TOKEN: Severity.HIGH,
    CredentialType.AZURE_CONNECTION_STRING: Severity.CRITICAL,
    CredentialType.SQL_CONNECTION_STRING: Severity.HIGH,
    CredentialType.JWT: Severity.HIGH,
    CredentialType.SLACK_TOKEN: Severity.HIGH,
    CredentialType.SENDGRID_KEY: Severity.HIGH,
    CredentialType.NPM_TOKEN: Severity.HIGH,
    CredentialType.AZURE_ENTRA_SECRET: Severity.CRITICAL,
    CredentialType.REDIS_PASSWORD: Severity.HIGH,
    CredentialType.MONGODB_CONNECTION: Severity.HIGH,
    CredentialType.SMTP_CREDENTIALS: Severity.MEDIUM,
    CredentialType.DOCKER_REGISTRY_TOKEN: Severity.HIGH,
    CredentialType.LDAP_BIND_PASSWORD: Severity.HIGH,
    CredentialType.SERVICE_BUS_CONNECTION: Severity.CRITICAL,
    CredentialType.JDBC_CONNECTION_STRING: Severity.HIGH,
    CredentialType.GENERIC_PASSWORD: Severity.MEDIUM,
    CredentialType.GENERIC_TOKEN: Severity.MEDIUM,
    CredentialType.UNKNOWN: Severity.LOW,
}


def process_variable(
    *,
    variable_name: str,
    value: str,
    resource: str,
    project: str = "",
    source_pipeline: str = "",
    source_group: str = "",
    store: FindingsStore | None = None,
    run_id: str = "",
    store_secrets: bool = False,
) -> tuple[CredentialTarget, float, str]:
    """Classify and score a single variable.

    Returns (target, score, label). If store and run_id are provided,
    also persists the finding. When store_secrets is True, the raw
    credential value is saved to the database for later retrieval.
    """
    cred_type = classify(value, variable_name)

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

    conf_score, conf_label, signals = score_target(target)
    target.confidence_score = conf_score
    target.confidence_label = conf_label
    target.confidence_signals = signals

    if store and run_id:
        severity = _SEVERITY_MAP.get(cred_type, Severity.MEDIUM)
        source = source_pipeline or source_group or resource
        metadata: dict[str, Any] = {
            "redacted_value": target.redacted_value,
            "confidence": conf_label,
            "confidence_score": conf_score,
            "confidence_signals": signals,
        }
        if source_pipeline:
            metadata["source"] = {"type": "pipeline", "name": source_pipeline}
        elif source_group:
            metadata["source"] = {"type": "variable_group", "name": source_group}

        finding = UnifiedFinding(
            id=uuid.uuid4().hex[:8],
            tool=ToolSource.CRED_SCAN,
            check_id=target.check_id,
            title=f"{cred_type.value}: {variable_name} in {source}",
            status=FindingStatus.FAIL,
            severity=severity,
            description=f"Potential {cred_type.value} found in variable '{variable_name}'.",
            resource=source,
            project=project,
            evidence={
                "credential_type": cred_type.value,
                "variable_name": variable_name,
            },
            remediation="Rotate the credential and store it in a proper secret manager.",
            metadata=metadata,
        )

        store.upsert_finding(
            finding, run_id,
            repo=resource, file_path=variable_name,
            pattern_id=target.check_id, secret_value=value,
            store_secret=store_secrets,
        )

    return target, conf_score, conf_label


def scan_variables(
    variables: list[dict[str, str]],
    *,
    resource: str = "",
    project: str = "",
    source_pipeline: str = "",
    source_group: str = "",
    store: FindingsStore | None = None,
    run_id: str = "",
    min_confidence: float = 0.0,
    store_secrets: bool = False,
) -> list[CredentialTarget]:
    """Batch classify and score a list of variables.

    Each dict in `variables` must have at least 'name' and 'value' keys.
    Returns targets that meet the min_confidence threshold.
    """
    results: list[CredentialTarget] = []

    for var in variables:
        name = var.get("name", "")
        value = var.get("value", "")
        if not name or not value:
            continue

        target, score, _ = process_variable(
            variable_name=name,
            value=value,
            resource=var.get("resource", resource),
            project=var.get("project", project),
            source_pipeline=var.get("source_pipeline", source_pipeline),
            source_group=var.get("source_group", source_group),
            store=store,
            run_id=run_id,
            store_secrets=store_secrets,
        )

        if score >= min_confidence:
            results.append(target)

    return results
