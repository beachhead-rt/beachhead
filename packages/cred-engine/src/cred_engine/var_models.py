"""Data models for pipeline variable credential scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CredentialType(Enum):  # noqa: B105
    AWS_ACCESS_KEY = "aws_access_key"
    GITHUB_PAT = "github_pat"
    GITHUB_APP_TOKEN = "github_app_token"  # nosec B105
    AZURE_STORAGE_KEY = "azure_storage_key"
    AZURE_SAS_TOKEN = "azure_sas_token"  # nosec B105
    AZURE_CONNECTION_STRING = "azure_connection_string"
    SQL_CONNECTION_STRING = "sql_connection_string"
    JWT = "jwt"
    SLACK_TOKEN = "slack_token"  # nosec B105
    SENDGRID_KEY = "sendgrid_key"
    NPM_TOKEN = "npm_token"  # nosec B105
    AZURE_ENTRA_SECRET = "azure_entra_secret"
    REDIS_PASSWORD = "redis_password"  # nosec B105
    MONGODB_CONNECTION = "mongodb_connection"
    SMTP_CREDENTIALS = "smtp_credentials"
    DOCKER_REGISTRY_TOKEN = "docker_registry_token"  # nosec B105
    LDAP_BIND_PASSWORD = "ldap_bind_password"  # nosec B105
    SERVICE_BUS_CONNECTION = "service_bus_connection"
    JDBC_CONNECTION_STRING = "jdbc_connection_string"
    GENERIC_PASSWORD = "generic_password"  # nosec B105
    GENERIC_TOKEN = "generic_token"  # nosec B105
    UNKNOWN = "unknown"


class ValidationStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    ERROR = "error"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass
class ValidationTool:
    name: str
    install: str
    category: str = "cli"


@dataclass
class ValidationGuide:
    commands: list[str] = field(default_factory=list)
    tools: list[ValidationTool] = field(default_factory=list)
    grants: str = ""
    risk: str = ""
    gui_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"commands": self.commands}
        if self.tools:
            d["tools"] = [{"name": t.name, "install": t.install, "category": t.category} for t in self.tools]
        if self.grants:
            d["grants"] = self.grants
        if self.risk:
            d["risk"] = self.risk
        if self.gui_steps:
            d["gui_steps"] = self.gui_steps
        return d


@dataclass
class CredentialTarget:
    check_id: str
    variable_name: str
    resource: str
    value: str = ""
    credential_type: CredentialType = CredentialType.UNKNOWN
    source_pipeline: str = ""
    source_pipeline_id: int = 0
    source_group: str = ""
    source_group_id: int = 0
    project: str = ""
    confidence_score: float = 0.0
    confidence_label: str = "unknown"
    confidence_signals: list[dict[str, Any]] = field(default_factory=list)

    @property
    def redacted_value(self) -> str:
        if not self.value:
            return "***"
        from cred_engine.models import redact_value
        return redact_value(self.value)


@dataclass
class ValidationResult:
    target: CredentialTarget
    status: ValidationStatus
    credential_type: CredentialType
    detail: str = ""
    identity: str = ""
    scopes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    commands: list[str] = field(default_factory=list)
    guide: ValidationGuide | None = None
    confidence_score: float = 0.0
    confidence_label: str = "unknown"
    triage_status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "variable_name": self.target.variable_name,
            "resource": self.target.resource,
            "project": self.target.project,
            "credential_type": self.credential_type.value,
            "status": self.status.value,
            "redacted_value": self.target.redacted_value,
            "confidence_score": self.confidence_score,
            "confidence_label": self.confidence_label,
            "triage_status": self.triage_status,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.identity:
            d["identity"] = self.identity
        if self.scopes:
            d["scopes"] = self.scopes
        if self.commands:
            d["commands"] = self.commands
        if self.guide:
            d["guide"] = self.guide.to_dict()
        if self.metadata:
            d["metadata"] = self.metadata
        if self.target.source_pipeline:
            d["source"] = {"type": "pipeline", "name": self.target.source_pipeline}
        elif self.target.source_group:
            d["source"] = {"type": "variable_group", "name": self.target.source_group}
        return d
