"""Docker registry credential validation via the v2 API.

Tests authentication against Docker Hub by default. For private registries,
looks for a registry host in sibling variables.
"""

from __future__ import annotations

import logging

import httpx

from cred_engine.var_models import (
    CredentialTarget,
    CredentialType,
    ValidationResult,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

_DOCKER_HUB_AUTH = "https://hub.docker.com/v2/users/login"

_REGISTRY_NAMES = frozenset({
    "docker_registry", "registry_url", "registry_host",
    "container_registry", "docker_server", "docker_host",
})
_USERNAME_NAMES = frozenset({
    "docker_username", "docker_user", "registry_username",
    "registry_user", "container_registry_user",
})


def _find_sibling(
    names: frozenset[str],
    all_targets: list[CredentialTarget],
    target: CredentialTarget,
    sibling_vars: dict[str, str],
) -> str:
    for name, value in sibling_vars.items():
        if name.lower().replace("-", "_").replace(".", "_") in names:
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
            if normalized in names:
                return other.value
    return ""


def validate_docker_registry(
    target: CredentialTarget,
    all_targets: list[CredentialTarget],
    sibling_vars: dict[str, str] | None = None,
) -> ValidationResult:
    """Validate Docker registry credentials via the v2 API (read-only)."""
    password = target.value.strip()
    siblings = sibling_vars or {}

    username = _find_sibling(_USERNAME_NAMES, all_targets, target, siblings)
    if not username:
        return ValidationResult(
            target=target,
            status=ValidationStatus.SKIPPED,
            credential_type=CredentialType.DOCKER_REGISTRY_TOKEN,
            detail="Docker token found but no username in sibling variables",
        )

    try:
        resp = httpx.post(
            _DOCKER_HUB_AUTH,
            json={"username": username, "password": password},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        return ValidationResult(
            target=target,
            status=ValidationStatus.ERROR,
            credential_type=CredentialType.DOCKER_REGISTRY_TOKEN,
            detail=f"HTTP error: {exc}",
        )

    if resp.status_code == 200:
        return ValidationResult(
            target=target,
            status=ValidationStatus.VALID,
            credential_type=CredentialType.DOCKER_REGISTRY_TOKEN,
            detail=f"Valid Docker Hub credentials for '{username}'",
            identity=username,
            metadata={"registry": "hub.docker.com", "username": username},
        )

    if resp.status_code == 401:
        return ValidationResult(
            target=target,
            status=ValidationStatus.INVALID,
            credential_type=CredentialType.DOCKER_REGISTRY_TOKEN,
            detail=f"Docker Hub rejected credentials for '{username}'",
            identity=username,
        )

    return ValidationResult(
        target=target,
        status=ValidationStatus.ERROR,
        credential_type=CredentialType.DOCKER_REGISTRY_TOKEN,
        detail=f"Unexpected response (HTTP {resp.status_code})",
    )
