"""Credential detection patterns — delegates to cred-engine.

Generates ScanQuery batches from cred-engine's pattern library for use
with the ADO ALM Search API.  Each ScanQuery combines related search
terms with OR to minimize API calls (TSTUs).

Modules that need raw regex matching should use ``cred_bridge.scan_text``
or ``cred_bridge.scan_snippet`` instead of accessing patterns directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cred_engine.patterns import PATTERNS as CE_PATTERNS

__all__ = ["ScanQuery", "SCAN_QUERIES"]


@dataclass(frozen=True)
class ScanQuery:
    id: str
    search_text: str
    pattern_names: tuple[str, ...]


def _group_patterns() -> list[ScanQuery]:
    """Build ScanQuery batches from cred-engine patterns.

    Groups patterns by semantic category (inferred from name/search terms)
    and combines their search terms with OR.  Each group becomes one ALM
    Search API call per project.
    """
    groups: dict[str, list[tuple[str, list[str]]]] = {
        "azure_conn_strings": [],
        "azure_secrets": [],
        "azure_service_keys": [],
        "sql_connection_strings": [],
        "aws_keys": [],
        "private_keys": [],
        "scm_tokens": [],
        "package_tokens": [],
        "saas_tokens": [],
        "webhook_urls": [],
        "monitoring_keys": [],
        "generic_secrets": [],
    }

    for p in CE_PATTERNS:
        name_lower = p.name.lower()
        terms = p.search_terms

        if any(kw in name_lower for kw in ("storage", "cosmos", "sas", "service bus", "event hub",
                                            "signalr", "notification")):
            groups["azure_conn_strings"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("client secret", "entra", "azure ad")):
            groups["azure_secrets"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("functions key", "container registry", "app insight")):
            groups["azure_service_keys"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("sql", "mysql", "postgres", "mongodb", "redis",
                                              "mssql", "odbc", "jdbc", "trusted_connection")):
            groups["sql_connection_strings"].append((p.name, terms))
        elif "aws" in name_lower:
            groups["aws_keys"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("private key", "pem", "pfx", "certificate")):
            groups["private_keys"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("github", "bearer", "jwt", "basic auth", "oauth")):
            groups["scm_tokens"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("nuget", "npm", "docker")):
            groups["package_tokens"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("webhook url", "slack webhook", "teams")):
            groups["webhook_urls"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("datadog", "statuspage", "pagerduty", "opsgenie",
                                              "launchdarkly")):
            groups["monitoring_keys"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("protocol url", "base64")):
            groups["sql_connection_strings"].append((p.name, terms))
        elif any(kw in name_lower for kw in ("slack", "sendgrid", "twilio", "stripe", "paypal")):
            groups["saas_tokens"].append((p.name, terms))
        else:
            groups["generic_secrets"].append((p.name, terms))

    queries: list[ScanQuery] = []
    for group_id, entries in groups.items():
        if not entries:
            continue

        all_terms: list[str] = []
        pattern_names: list[str] = []
        for pname, terms in entries:
            pattern_names.append(pname)
            for term in terms:
                clean = re.sub(r"\s+ext:\S+", "", term).strip()
                if clean and clean not in all_terms:
                    all_terms.append(clean)

        if len(all_terms) > 8:
            all_terms = all_terms[:8]

        search_text = " OR ".join(f'"{t}"' if " " in t else t for t in all_terms)
        queries.append(ScanQuery(
            id=group_id,
            search_text=search_text,
            pattern_names=tuple(pattern_names),
        ))

    return queries


SCAN_QUERIES: tuple[ScanQuery, ...] = tuple(_group_patterns())


_CRED_INDICATOR_RE = re.compile(
    r"(password|secret|key|token|AccountKey|AKIA|ghp_|gho_|ghs_|"
    r"DefaultEndpointsProtocol|connectionstring|client_secret|"
    r"bearer|Authorization|SharedAccessKey|SG\.|sk_live|sk_test|"
    r"eyJ[A-Za-z0-9]|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|"
    r"hooks\.slack\.com|webhook\.office\.com|sdk-[a-f0-9]|"
    r"stpg-|dd-app-|amqps?://|pagerduty|opsgenie|_b64)",
    re.IGNORECASE,
)

_VALUE_LIKE_RE = re.compile(r"[=:]\s*\S{8,}|Bearer\s+\S{8,}", re.IGNORECASE)


def looks_like_credential(text: str) -> bool:
    """Quick heuristic check for credential-like content."""
    return bool(_CRED_INDICATOR_RE.search(text) and _VALUE_LIKE_RE.search(text))
