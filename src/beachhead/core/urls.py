"""ADO resource ID → web URL mapping.

Pure functions shared by both CLI and TUI — no framework dependencies.
"""

from __future__ import annotations

import re

_ADO_WEB = "https://dev.azure.com"

_RESOURCE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/vargroup/(\d+)$"),
        "{base}/{1}/{2}/_library?itemType=VariableGroups&view=VariableGroupView&variableGroupId={3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/pipeline/(\d+)$"),
        "{base}/{1}/{2}/_build?definitionId={3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/build/(\d+)$"),
        "{base}/{1}/{2}/_build?definitionId={3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/build/(\d+)/log/\d+$"),
        "{base}/{1}/{2}/_build/results?buildId={3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/release/(\d+)$"),
        "{base}/{1}/{2}/_release?definitionId={3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/repo/([^/]+)$"),
        "{base}/{1}/{2}/_git/{3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/endpoint/([^/]+)$"),
        "{base}/{1}/{2}/_settings/adminservices?resourceId={3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/wi/(\d+)$"),
        "{base}/{1}/{2}/_workitems/edit/{3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/feed/([^/]+)$"),
        "{base}/{1}/{2}/_artifacts/feed/{3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/feed/([^/]+)$"),
        "{base}/{1}/_artifacts/feed/{2}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/wiki/(.+)$"),
        "{base}/{1}/{2}/_wiki/wikis/{3}",
    ),
    (
        re.compile(r"^ado://([^/]+)/([^/]+)/policy/(\d+)$"),
        "{base}/{1}/{2}/_settings/repositories?_a=policiesMid",
    ),
    (
        re.compile(r"^ado://([^/]+)/pool/(\d+)$"),
        "{base}/{1}/_settings/agentpools?poolId={2}",
    ),
    (
        re.compile(r"^ado://([^/]+)/pool/(\d+)/agent/\d+$"),
        "{base}/{1}/_settings/agentpools?poolId={2}",
    ),
    (
        re.compile(r"^ado://([^/]+)/extension/(.+)$"),
        "{base}/{1}/_settings/extensions",
    ),
    (
        re.compile(r"^ado://([^/]+)/hook/(.+)$"),
        "{base}/{1}/_settings/serviceHooks",
    ),
]


def resource_id_to_url(resource_id: str) -> str:
    """Convert an ado:// resource ID to an ADO web URL, or return ''."""
    if not resource_id or not resource_id.startswith("ado://"):
        return ""
    for pattern, template in _RESOURCE_PATTERNS:
        m = pattern.match(resource_id)
        if m:
            url = template.replace("{base}", _ADO_WEB)
            for i, group in enumerate(m.groups(), 1):
                url = url.replace(f"{{{i}}}", group)
            return url
    return ""


def resolve_finding_url(details: dict, resource_id: str = "") -> str:
    """Return the best browser URL for a finding: explicit ado_url > derived from resource_id."""
    url = (details or {}).get("ado_url", "")
    if url:
        return url
    return resource_id_to_url(resource_id)
