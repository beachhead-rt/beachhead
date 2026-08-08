"""Data models for the credential scanning engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    FAIL = "fail"
    WARN = "warn"
    PASS = "pass"
    ERROR = "error"
    SKIP = "skip"
    INFO = "info"
    UNKNOWN = "unknown"


class ToolSource(Enum):
    CRED_SCAN = "cred-scan"


def redact_value(secret: str, *, keep: int = 4) -> str:
    """Redact a secret for safe display, keeping *keep* chars on each end."""
    if len(secret) > keep * 2 + 4:
        return secret[:keep] + "****" + secret[-keep:]
    return "****"


@dataclass
class UnifiedFinding:
    """A single credential finding, normalized for storage and display."""

    id: str
    tool: ToolSource
    check_id: str
    title: str
    status: FindingStatus
    severity: Severity
    description: str
    resource: str = ""
    project: str = ""
    url: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    commands: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "tool": self.tool.value,
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "description": self.description,
        }
        if self.resource:
            d["resource"] = self.resource
        if self.project:
            d["project"] = self.project
        if self.url:
            d["url"] = self.url
        if self.evidence:
            d["evidence"] = self.evidence
        if self.remediation:
            d["remediation"] = self.remediation
        if self.commands:
            d["commands"] = self.commands
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class ToolReport:
    """Aggregated results from a single scan run."""

    tool: ToolSource
    findings: list[UnifiedFinding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    source_file: str = ""

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def by_status(self) -> dict[FindingStatus, int]:
        counts: dict[FindingStatus, int] = {}
        for f in self.findings:
            counts[f.status] = counts.get(f.status, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.value,
            "total": self.total,
            "by_severity": {k.value: v for k, v in self.by_severity.items()},
            "by_status": {k.value: v for k, v in self.by_status.items()},
            "findings": [f.to_dict() for f in self.findings],
        }
