"""Validator dispatch — routes credential targets to the right validator."""

from __future__ import annotations

import logging

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)
from cred_engine.var_validators.aws import validate_aws_key
from cred_engine.var_validators.azure_entra import validate_entra_secret
from cred_engine.var_validators.azure_storage import validate_azure_storage
from cred_engine.var_validators.connection_string import validate_connection_string
from cred_engine.var_validators.docker_registry import validate_docker_registry
from cred_engine.var_validators.github import validate_github_pat
from cred_engine.var_validators.jwt_check import validate_jwt
from cred_engine.var_validators.ldap import validate_ldap
from cred_engine.var_validators.mongodb import validate_mongodb
from cred_engine.var_validators.npm import validate_npm_token
from cred_engine.var_validators.redis_check import validate_redis
from cred_engine.var_validators.sendgrid import validate_sendgrid_key
from cred_engine.var_validators.slack import validate_slack_token
from cred_engine.var_validators.smtp import validate_smtp
from cred_engine.var_validators.sql import validate_sql

logger = logging.getLogger(__name__)

_AWS_SECRET_NAMES = frozenset({
    "aws_secret_access_key",
    "awssecretaccesskey",
    "aws_secret_key",
    "awssecretkey",
    "secret_access_key",
    "secretaccesskey",
})


def _find_aws_secret(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str],
) -> str | None:
    """Find the AWS secret access key paired with an access key ID.

    Looks in sibling variables from the same pipeline/group, then checks
    all targets for a matching resource.
    """
    for name, value in sibling_vars.items():
        if name.lower().replace("-", "_").replace(".", "_") in _AWS_SECRET_NAMES:
            return value

    for other in all_targets:
        if other is target:
            continue
        same_source = (
            (target.source_pipeline and target.source_pipeline == other.source_pipeline)
            or (target.source_group and target.source_group == other.source_group)
        )
        if same_source:
            normalized = other.variable_name.lower().replace("-", "_").replace(".", "_")
            if normalized in _AWS_SECRET_NAMES:
                return other.value

    return None


def validate_target(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str] | None = None,
) -> ValidationResult:
    """Validate a single credential target using the appropriate validator."""
    cred_type = target.credential_type

    if cred_type in (CredentialType.GITHUB_PAT, CredentialType.GITHUB_APP_TOKEN):
        return validate_github_pat(target)

    if cred_type == CredentialType.JWT:
        return validate_jwt(target)

    if cred_type == CredentialType.SLACK_TOKEN:
        return validate_slack_token(target)

    if cred_type == CredentialType.SENDGRID_KEY:
        return validate_sendgrid_key(target)

    if cred_type == CredentialType.NPM_TOKEN:
        return validate_npm_token(target)

    if cred_type == CredentialType.AWS_ACCESS_KEY:
        secret = _find_aws_secret(target, all_targets, sibling_vars or {})
        if not secret:
            return ValidationResult(
                target=target,
                status=ValidationStatus.SKIPPED,
                credential_type=CredentialType.AWS_ACCESS_KEY,
                detail="Access Key ID found but no matching Secret Access Key in sibling variables",
            )
        return validate_aws_key(target, secret)

    if cred_type == CredentialType.AZURE_STORAGE_KEY:
        return validate_azure_storage(target)

    if cred_type == CredentialType.SQL_CONNECTION_STRING:
        return validate_sql(target)

    if cred_type in (CredentialType.AZURE_CONNECTION_STRING, CredentialType.AZURE_SAS_TOKEN):
        return validate_connection_string(target)

    if cred_type == CredentialType.AZURE_ENTRA_SECRET:
        return validate_entra_secret(target, all_targets, sibling_vars or {})

    if cred_type == CredentialType.REDIS_PASSWORD:
        return validate_redis(target, all_targets, sibling_vars or {})

    if cred_type == CredentialType.MONGODB_CONNECTION:
        return validate_mongodb(target)

    if cred_type == CredentialType.SMTP_CREDENTIALS:
        return validate_smtp(target, all_targets, sibling_vars or {})

    if cred_type == CredentialType.DOCKER_REGISTRY_TOKEN:
        return validate_docker_registry(target, all_targets, sibling_vars or {})

    if cred_type == CredentialType.LDAP_BIND_PASSWORD:
        return validate_ldap(target, all_targets, sibling_vars or {})

    if cred_type in (CredentialType.GENERIC_PASSWORD, CredentialType.GENERIC_TOKEN):
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=cred_type,
            detail=(
                f"Variable '{target.variable_name}' has a credential-like name "
                f"but the value type could not be identified for automated validation"
            ),
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.SKIPPED,
        credential_type=CredentialType.UNKNOWN,
        detail="Unknown credential type — cannot validate",
    )


def validate_all(
    targets: list[CredentialTarget],
    sibling_vars_map: dict[str, dict[str, str]] | None = None,
) -> list[ValidationResult]:
    """Validate all credential targets."""
    results: list[ValidationResult] = []
    vars_map = sibling_vars_map or {}

    for target in targets:
        cache_key = ""
        if target.source_pipeline_id:
            cache_key = f"pipeline:{target.project}:{target.source_pipeline_id}"
        elif target.source_group_id:
            cache_key = f"group:{target.project}:{target.source_group_id}"

        siblings = vars_map.get(cache_key, {})
        result = validate_target(target, targets, siblings)
        results.append(result)

    return results
