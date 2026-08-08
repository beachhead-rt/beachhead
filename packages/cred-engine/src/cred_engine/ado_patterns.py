"""Shared credential patterns and text utilities for ADO surface scanners."""

from __future__ import annotations

import html
import re

_HTML_TAG_RE = re.compile(r"<[^>]+>")

CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # --- Cloud provider keys ---
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Azure Storage Key", re.compile(r"(?i)DefaultEndpointsProtocol=.*AccountName=.*AccountKey=")),
    ("Azure SAS Token", re.compile(r"(?i)SharedAccessSignature\s*=|[?&]sig=[A-Za-z0-9%+/=]{20,}")),
    ("Azure Connection String", re.compile(r"(?i)AccountKey=\s*[A-Za-z0-9+/=]{40,}")),
    (
        "Azure Client Secret",
        re.compile(r"(?i)(client.?secret|tenant.?secret)\s*[:=]\s*[A-Za-z0-9~_.]{20,}"),
    ),
    ("SQL Connection String", re.compile(r"(?i)(Server|Data\s*Source)=.*Password=")),
    ("Service URL Credentials", re.compile(r"(?i)url\s*=\s*https?://[^;]+;\s*username\s*=\s*[^;]+;\s*password\s*=")),
    ("MongoDB Connection", re.compile(r"mongodb(\+srv)?://[^:]+:[^@]+@")),
    # --- AI / LLM API keys ---
    ("OpenAI API Key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("Google AI API Key", re.compile(r"AIza[A-Za-z0-9_\-]{35}")),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("Replicate API Token", re.compile(r"r8_[A-Za-z0-9]{20,}")),
    ("Cohere API Key", re.compile(r"(?i)cohere[_-]?(?:api[_-]?)?key\s*[:=]\s*[\"']?[A-Za-z0-9]{20,}")),
    (
        "Azure OpenAI Key",
        re.compile(r"(?i)(azure[_-]?openai|openai)[_-]?(?:api[_-]?)?key\s*[:=]\s*[\"']?[a-f0-9]{32}"),
    ),
    # --- AI configuration leaks ---
    (
        "LLM System Prompt",
        re.compile(
            r"(?i)(system[_-]?prompt|system[_-]?message|system[_-]?instruction)"
            r"\s*[:=]\s*[\"'][^\"']{20,}"
        ),
    ),
    (
        "LLM Model Endpoint",
        re.compile(
            r"(?i)(openai|anthropic|azure\.openai|ai\.azure)"
            r"\.(com|azure\.com)/[^\s\"']{10,}"
        ),
    ),
    # --- SCM / CI tokens ---
    ("GitHub PAT", re.compile(r"ghp_[A-Za-z0-9]{36,}")),
    ("GitHub App Token", re.compile(r"ghs_[A-Za-z0-9]{36,}")),
    ("NPM Token", re.compile(r"npm_[A-Za-z0-9]{36,}")),
    ("NuGet API Key", re.compile(r"(?i)(nuget|apikey)\s*[:=]\s*[\"']?oy2[A-Za-z0-9]{30,}")),
    # --- Messaging / SaaS ---
    ("Slack Token", re.compile(r"xox[bpsa]-[A-Za-z0-9\-]{10,}")),
    ("SendGrid Key", re.compile(r"SG\.[A-Za-z0-9_\-]{20,}")),
    # --- Cryptographic material ---
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("PEM Private Key", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
    ("OpenSSH Private Key", re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----")),
    # --- MSSQL-specific ---
    ("MSSQL sqlcmd Password", re.compile(r"(?i)sqlcmd\s+.*-P\s+([^\s\"';]+)")),
    (
        "MSSQL ODBC Connection String",
        re.compile(r"(?i)Driver\s*=.*(?:SQL\s*Server|ODBC\s*Driver).*(?:Pwd|Password)\s*=\s*[^;\"'\s]{3,}"),
    ),
    (
        "MSSQL Trusted_Connection=false",
        re.compile(r"(?i)Trusted_Connection\s*=\s*(?:false|no)\s*;.*Password\s*=\s*[^;\"'\s]{3,}"),
    ),
    (
        "MSSQL SqlConnection in Code",
        re.compile(r"(?i)(?:SqlConnection|SqlClient).*Password\s*=\s*[^;\"'\s]{3,}"),
    ),
    ("JDBC SQL Server Connection", re.compile(r"(?i)jdbc:sqlserver.*password\s*=\s*[^\s;\"'&]{3,}")),
    ("SSIS Project Params Password", re.compile(r"(?i)<Value>[^<]{8,}</Value>")),
    # --- .NET credential constructors ---
    (
        "NetworkCredential Hardcoded",
        re.compile(r"""(?i)NetworkCredential\(\s*(?:@?"[^"]*"\s*,\s*)?@?"[^"]{3,}"\s*\)"""),
    ),
    (
        "VssBasicCredential Inline Token",
        re.compile(r"""(?i)VssBasicCredential\(\s*"[^"]*"\s*,\s*"[^"]{8,}"\s*\)"""),
    ),
    # --- Jenkins CI secrets ---
    (
        "Jenkins Encrypted Password",
        re.compile(r"<(?:password|hudsonSecret|secret)>[^<]{8,}</(?:password|hudsonSecret|secret)>"),
    ),
    (
        "Jenkins Auth / Build Token",
        re.compile(r"<(?:authToken|slackToken|token)>[^<]{4,}</(?:authToken|slackToken|token)>"),
    ),
    # --- Hardcoded default passwords ---
    (
        "Hardcoded Default Password",
        re.compile(
            r"(?i)(?:password|pwd)\s*[:=]\s*[\"']?"
            r"(?:adminadmin|password123|P@ssw0rd|changeme|Welcome1)\b"
        ),
    ),
    # --- Generic assignments (broadest — keep last to avoid masking specific matches) ---
    (
        "Generic Password Assignment",
        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}"),
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}"),
    ),
    (
        "Generic Token Assignment",
        re.compile(
            r"(?i)(auth[_-]?token|access[_-]?token|bearer)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-.]{20,}"
        ),
    ),
]


def redact_match(text: str, keep: int = 6) -> str:
    """Mask the middle of a matched secret, keeping *keep* chars on each end."""
    if len(text) <= keep * 2:
        return "****"
    return text[:keep] + "****" + text[-keep:]


def strip_html(text: str) -> str:
    """Remove HTML tags and decode common entities."""
    return html.unescape(_HTML_TAG_RE.sub(" ", text))


