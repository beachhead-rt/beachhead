"""Classify raw credential values into credential types.

Two-stage detection:
1. Value patterns -- 17 regexes matched against the credential value itself
2. Name hints -- 25 variable name substrings as fallback

To adapt: add patterns for services your target uses, add name hints
for your organization's variable naming conventions.
"""

from __future__ import annotations

import re

from cred_engine.var_models import CredentialType

_PATTERNS: list[tuple[CredentialType, re.Pattern[str]]] = [
    (CredentialType.AWS_ACCESS_KEY, re.compile(r"^AKIA[0-9A-Z]{16}$")),
    (CredentialType.GITHUB_PAT, re.compile(r"^ghp_[A-Za-z0-9]{36,}$")),
    (CredentialType.GITHUB_APP_TOKEN, re.compile(r"^ghs_[A-Za-z0-9]{36,}$")),
    (CredentialType.SLACK_TOKEN, re.compile(r"^xox[bpsa]-[A-Za-z0-9\-]+")),
    (CredentialType.SENDGRID_KEY, re.compile(r"^SG\.[A-Za-z0-9_\-]{20,}")),
    (CredentialType.NPM_TOKEN, re.compile(r"^npm_[A-Za-z0-9]{36,}$")),
    (CredentialType.JWT, re.compile(r"^(eyJ[A-Za-z0-9_-]{10,}\.){2}")),
    (
        CredentialType.AZURE_STORAGE_KEY,
        re.compile(r"(?i)DefaultEndpointsProtocol=.*AccountName=.*AccountKey="),
    ),
    (
        CredentialType.AZURE_SAS_TOKEN,
        re.compile(r"(?i)SharedAccessSignature|[?&]sig=[A-Za-z0-9%+/=]{20,}"),
    ),
    (
        CredentialType.SQL_CONNECTION_STRING,
        re.compile(r"(?i)(Server|Data\s*Source)=.*Password="),
    ),
    (
        CredentialType.AZURE_CONNECTION_STRING,
        re.compile(r"(?i)AccountKey=\s*[A-Za-z0-9+/=]{40,}"),
    ),
    (
        CredentialType.AZURE_ENTRA_SECRET,
        re.compile(r"(?i)(client.?secret|tenant.?secret).*[A-Za-z0-9~_.]{30,}"),
    ),
    (
        CredentialType.MONGODB_CONNECTION,
        re.compile(r"mongodb(\+srv)?://[^:]+:[^@]+@"),
    ),
    (
        CredentialType.REDIS_PASSWORD,
        re.compile(r"redis://[^:]*:[^@]+@"),
    ),
    (
        CredentialType.DOCKER_REGISTRY_TOKEN,
        re.compile(r"(?i)docker(hub)?[_.]?(password|token|registry)", re.IGNORECASE),
    ),
    (
        CredentialType.SERVICE_BUS_CONNECTION,
        re.compile(r"(?i)Endpoint=sb://.*SharedAccessKeyName=.*SharedAccessKey="),
    ),
    (
        CredentialType.JDBC_CONNECTION_STRING,
        re.compile(r"(?i)jdbc:sqlserver://.*password="),
    ),
]

_NAME_HINTS: dict[str, CredentialType] = {
    "redis_password": CredentialType.REDIS_PASSWORD,
    "redis_auth": CredentialType.REDIS_PASSWORD,
    "redis_key": CredentialType.REDIS_PASSWORD,
    "smtp_password": CredentialType.SMTP_CREDENTIALS,
    "smtp_pass": CredentialType.SMTP_CREDENTIALS,
    "email_password": CredentialType.SMTP_CREDENTIALS,
    "mail_password": CredentialType.SMTP_CREDENTIALS,
    "ldap_password": CredentialType.LDAP_BIND_PASSWORD,
    "ldap_bind": CredentialType.LDAP_BIND_PASSWORD,
    "bind_password": CredentialType.LDAP_BIND_PASSWORD,
    "client_secret": CredentialType.AZURE_ENTRA_SECRET,
    "servicebus_connection": CredentialType.SERVICE_BUS_CONNECTION,
    "shared_access_key": CredentialType.SERVICE_BUS_CONNECTION,
    "jdbc_url": CredentialType.JDBC_CONNECTION_STRING,
    "jdbc_password": CredentialType.JDBC_CONNECTION_STRING,
    "spring_datasource_password": CredentialType.JDBC_CONNECTION_STRING,
    "password": CredentialType.GENERIC_PASSWORD,
    "passwd": CredentialType.GENERIC_PASSWORD,
    "pwd": CredentialType.GENERIC_PASSWORD,
    "token": CredentialType.GENERIC_TOKEN,
    "access_token": CredentialType.GENERIC_TOKEN,
    "auth_token": CredentialType.GENERIC_TOKEN,
    "apikey": CredentialType.GENERIC_TOKEN,
    "api_key": CredentialType.GENERIC_TOKEN,
    "secret": CredentialType.GENERIC_TOKEN,
}


def classify(value: str, variable_name: str = "") -> CredentialType:
    """Classify a credential value into a known type.

    Tries value-based pattern matching first, falls back to variable name hints.
    """
    if not value:
        return CredentialType.UNKNOWN

    stripped = value.strip()
    for cred_type, pattern in _PATTERNS:
        if pattern.search(stripped):
            return cred_type

    if variable_name:
        normalized = variable_name.lower().replace("-", "_").replace(".", "_")
        for name_part, cred_type in _NAME_HINTS.items():
            if name_part in normalized:
                return cred_type

    return CredentialType.UNKNOWN
