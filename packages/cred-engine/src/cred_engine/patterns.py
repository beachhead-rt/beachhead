"""Credential patterns — regex definitions for detecting secrets in source code.

Each pattern defines:
- search_terms: keywords for coarse-grained search (platform-specific)
- secret_regex: fine-grained extraction regex with capture group(1)
- min_entropy: Shannon entropy threshold for the extracted secret
- severity: finding severity level
- extensions: optional file extension filter

To adapt for your target:
- Remove patterns you don't need
- Add patterns specific to your environment
- Adjust search_terms for your platform's search syntax
"""

from __future__ import annotations

import dataclasses

from cred_engine.models import Severity

_CFG_EXT = ("config", "json", "xml", "yaml", "yml")
_ALL_EXT = ("config", "json", "xml", "yaml", "yml", "env", "properties", "ini")
_KEY_EXT = ("pem", "key", "p12", "pfx", "ppk")


@dataclasses.dataclass(frozen=True, slots=True)
class CredPattern:
    """A credential detection pattern."""

    name: str
    search_terms: list[str]
    severity: Severity
    extensions: tuple[str, ...] = ()
    min_entropy: float | None = None
    secret_regex: str | None = None


PATTERNS: list[CredPattern] = [
    # --- Azure infrastructure ---
    CredPattern(
        "Azure Storage / Cosmos Key",
        ["AccountKey=", "account_key ="],
        Severity.CRITICAL,
        _CFG_EXT,
        min_entropy=3.5,
        secret_regex=r"(?i)(?:AccountKey|account_key)\s*=\s*([A-Za-z0-9+/=]{20,})",
    ),
    CredPattern(
        "Azure SAS Token",
        ["SharedAccessSignature sig=", "sv= sig="],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=3.0,
        secret_regex=r"(?i)sig=([A-Za-z0-9%+/=]{20,})",
    ),
    CredPattern(
        "Azure Service Bus / Event Hub",
        ["SharedAccessKey=", "SharedAccessKeyName="],
        Severity.CRITICAL,
        _CFG_EXT,
        min_entropy=3.5,
        secret_regex=r"(?i)SharedAccessKey=([A-Za-z0-9+/=]{20,})",
    ),
    CredPattern(
        "Cosmos DB Connection",
        ["AccountEndpoint= AccountKey="],
        Severity.CRITICAL,
        _CFG_EXT,
        min_entropy=3.5,
        secret_regex=r"(?i)AccountKey=([A-Za-z0-9+/=]{20,})",
    ),
    CredPattern(
        "Azure AD / Entra Client Secret",
        ["client_secret", "ClientSecret=", "clientSecret:"],
        Severity.CRITICAL,
        min_entropy=2.5,
        secret_regex=r"""(?i)(?:client_?secret|clientSecret)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})""",
    ),
    CredPattern(
        "Azure App Insights Key",
        ["InstrumentationKey=", "APPINSIGHTS_INSTRUMENTATIONKEY"],
        Severity.MEDIUM,
        _CFG_EXT,
        min_entropy=3.0,
        secret_regex=r"(?i)InstrumentationKey[=:]\s*\"?([0-9a-f-]{36})",
    ),
    CredPattern(
        "Azure SignalR / Notification Hub",
        ["Endpoint= AccessKey=", "NotificationHub ConnectionString"],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=3.5,
        secret_regex=r"(?i)AccessKey=([A-Za-z0-9+/=]{20,})",
    ),
    CredPattern(
        "Azure Container Registry",
        ["azurecr.io password", "acrPassword"],
        Severity.HIGH,
        min_entropy=2.5,
        secret_regex=r"""(?i)(?:password|acrPassword)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})""",
    ),
    CredPattern(
        "Azure Functions Key",
        ["x-functions-key", "AzureWebJobsStorage="],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"(?i)(?:x-functions-key|AzureWebJobsStorage)\s*[:=]\s*\"?([^\s\"';]{20,})",
    ),
    # --- SQL / Database connection strings ---
    CredPattern(
        "SQL Connection String (Password)",
        ["Password= Data Source=", "Password= Server=", "pwd= Server=", "pwd= Data Source="],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=2.0,
        secret_regex=r"(?i)(?:Password|pwd)\s*=\s*([^;\"'\s,]{3,})",
    ),
    CredPattern(
        "SQL Password (Initial Catalog)",
        ["Password= Initial Catalog="],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=2.0,
        secret_regex=r"(?i)Password\s*=\s*([^;\"'\s,]{3,})",
    ),
    CredPattern(
        "MySQL / PostgreSQL Password",
        ["mysql:// password", "postgresql:// password", "Host= Password=", "Server= User Id= Password="],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=2.0,
        secret_regex=r"(?i)(?:Password|password)\s*=\s*([^;\"'\s,]{3,})",
    ),
    CredPattern(
        "MongoDB Connection String",
        ["mongodb:// password", "mongodb+srv://"],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=2.5,
        secret_regex=r"mongodb(?:\+srv)?://[^:]+:([^@\s]{3,})@",
    ),
    CredPattern(
        "Redis Password / Auth",
        ["redis password=", "redis_password", "requirepass"],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=2.0,
        secret_regex=r"""(?i)(?:redis_?password|requirepass)\s*[:=]\s*["']?([^\s"',;}{]{3,})""",
    ),
    # --- AWS ---
    CredPattern(
        "AWS Access Key ID",
        ["AKIA"],
        Severity.CRITICAL,
        min_entropy=3.0,
        secret_regex=r"(AKIA[0-9A-Z]{16})",
    ),
    CredPattern(
        "AWS Secret Access Key",
        ["aws_secret_access_key", "SecretAccessKey=", "aws_secret_key"],
        Severity.CRITICAL,
        min_entropy=4.0,
        secret_regex=r"""(?i)(?:aws_?)?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9+/=]{30,})""",
    ),
    # --- Private keys & certificates ---
    CredPattern(
        "PEM / RSA / SSH Private Key",
        ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY"],
        Severity.CRITICAL,
        _KEY_EXT,
        min_entropy=4.5,
        secret_regex=r"-----BEGIN[A-Z ]+KEY-----\s*([A-Za-z0-9+/=\s]{40,})",
    ),
    CredPattern(
        "PFX / Certificate Password",
        ["pfx password", "CertificatePassword", "X509Certificate2 password"],
        Severity.HIGH,
        min_entropy=2.0,
        secret_regex=r"""(?i)(?:pfx\s+password|CertificatePassword|X509Certificate2\s+password)\s*[:=]\s*["']?([^\s"',;}{]{3,})""",
    ),
    # --- API tokens & service keys ---
    CredPattern(
        "GitHub PAT / App Token",
        ["ghp_", "ghs_", "github_pat_"],
        Severity.HIGH,
        min_entropy=3.5,
        secret_regex=r"(gh[ps]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})",
    ),
    CredPattern(
        "NuGet / NPM Auth Token",
        ["_authToken=", "ClearTextPassword", "NuGetApiKey", "nuget setapikey"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:_authToken|ClearTextPassword|NuGetApiKey)\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{20,})""",
    ),
    CredPattern(
        "Slack Token",
        ["xoxb-", "xoxp-", "xoxr-", "xoxa-"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"(xox[bpra]-[A-Za-z0-9-]{10,})",
    ),
    CredPattern(
        "SendGrid API Key",
        ["SG.", "SENDGRID_API_KEY"],
        Severity.HIGH,
        min_entropy=3.5,
        secret_regex=r"(SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
    ),
    CredPattern(
        "Twilio Auth",
        ["TWILIO_AUTH_TOKEN", "twilio_token", "AccountSid= AuthToken="],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:TWILIO_AUTH_TOKEN|twilio_token|AuthToken)\s*[:=]\s*["']?([0-9a-f]{32})""",
    ),
    CredPattern(
        "Stripe Secret Key",
        ["sk_live_", "sk_test_", "rk_live_"],
        Severity.CRITICAL,
        min_entropy=3.5,
        secret_regex=r"([sr]k_(?:live|test)_[A-Za-z0-9]{20,})",
    ),
    CredPattern(
        "PayPal / Braintree Secret",
        ["paypal_secret", "braintree private_key", "PAYPAL_CLIENT_SECRET"],
        Severity.HIGH,
        min_entropy=2.5,
        secret_regex=r"""(?i)(?:paypal_secret|PAYPAL_CLIENT_SECRET|private_key)\s*[:=]\s*["']?([^\s"',;}{]{8,})""",
    ),
    # --- Webhook URLs ---
    CredPattern(
        "Slack Webhook URL",
        ["hooks.slack.com/services"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
    ),
    CredPattern(
        "Teams / Office 365 Webhook URL",
        ["webhook.office.com"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(https://[A-Za-z0-9.-]+\.webhook\.office\.com/webhookb2/[^\s"',;]+)""",
    ),
    # --- Monitoring / alerting service keys ---
    CredPattern(
        "LaunchDarkly SDK Key",
        ["sdk-", "LAUNCHDARKLY"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"(sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
    ),
    CredPattern(
        "Datadog API / App Key",
        ["DD_API_KEY", "DD_APP_KEY", "datadog"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:DD_(?:API|APP)_KEY|datadog[_-]?(?:api|app)[_-]?key)["']?\s*[:=]\s*["']?([a-f0-9]{32}|dd-app-[a-f0-9]+)""",
    ),
    CredPattern(
        "StatusPage API Key",
        ["stpg-", "statuspage"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"(stpg-[a-zA-Z0-9]{20,})",
    ),
    CredPattern(
        "PagerDuty Integration Key",
        ["pagerduty", "PD_INTEGRATION_KEY"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:pagerduty|pd)[_-](?:integration[_-]|routing[_-])?key["']?\s*[:=]\s*["']?([a-f0-9]{32})""",
    ),
    CredPattern(
        "OpsGenie API Key",
        ["opsgenie"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)opsgenie[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})""",
    ),
    # --- Protocol URLs with embedded credentials ---
    CredPattern(
        "Protocol URL with Embedded Credentials",
        ["amqp://", "amqps://", "redis://", "nats://", "mqtt://"],
        Severity.HIGH,
        min_entropy=2.0,
        secret_regex=r"""(?i)(?:amqp|redis|mqtt|stomp|nats)s?://[^:@\s"']+:(.+)@(?:[a-z][a-z0-9.-]+\.[a-z]{2,}|localhost|\d+\.\d+\.\d+\.\d+)(?:[:/\s"',]|$)""",
    ),
    # --- Base64-encoded credential fields ---
    CredPattern(
        "Base64-Encoded Credential",
        ["_b64", "_base64", "pass_b64", "psk_b64", "secret_b64"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:pass(?:word)?|psk|secret|key|token|credential|auth)[_-]?b(?:ase)?64["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{16,}={0,2})""",
    ),
    # --- SMTP & email ---
    CredPattern(
        "SMTP Credentials",
        ["smtp password", "SmtpPassword", "mail.smtp.password", "EMAIL_PASSWORD"],
        Severity.HIGH,
        min_entropy=2.0,
        secret_regex=r"""(?i)(?:smtp\s*password|SmtpPassword|mail\.smtp\.password|EMAIL_PASSWORD)\s*[:=]\s*["']?([^\s"',;}{]{3,})""",
    ),
    # --- Generic auth patterns ---
    CredPattern(
        "API Key (config files)",
        ["api_key =", "apiKey:", "ApiKey="],
        Severity.HIGH,
        _CFG_EXT,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:api_?key|app_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})""",
    ),
    CredPattern(
        "Bearer / JWT Token",
        ["Bearer eyJ", "Authorization: Bearer"],
        Severity.HIGH,
        min_entropy=3.5,
        secret_regex=r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)",
    ),
    CredPattern(
        "Basic Auth Header",
        ["Authorization: Basic", "BasicAuth password"],
        Severity.HIGH,
        min_entropy=2.5,
        secret_regex=r"(?i)(?:Authorization:\s*Basic|BasicAuth\s+password)\s+([A-Za-z0-9+/=]{8,})",
    ),
    CredPattern(
        "OAuth Secret / Refresh Token",
        ["client_secret=", "refresh_token=", "oauth_token=", "access_token="],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:client_secret|refresh_token|oauth_token|access_token)\s*=\s*["']?([^\s"',;&]{10,})""",
    ),
    CredPattern(
        "Webhook Secret",
        ["webhook_secret", "WebhookSecret", "signing_secret", "WEBHOOK_TOKEN", "whsec_"],
        Severity.MEDIUM,
        _CFG_EXT,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:webhook_?secret|signing_secret|WEBHOOK_TOKEN)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})""",
    ),
    CredPattern(
        "Encryption / Signing Key",
        ["EncryptionKey=", "signing_key=", "MachineKey validationKey", "decryptionKey="],
        Severity.CRITICAL,
        _CFG_EXT,
        min_entropy=3.5,
        secret_regex=r"(?i)(?:EncryptionKey|signing_key|validationKey|decryptionKey)\s*=\s*\"?([A-Fa-f0-9]{32,})",
    ),
    # --- Hardcoded passwords in config ---
    CredPattern(
        "Password in Config (appSettings)",
        ["password value= ext:config", "Password ext:json"],
        Severity.HIGH,
        min_entropy=2.0,
        secret_regex=r"""(?i)password["']?\s*[:=]\s*["']?([^\s"',;}{]{3,})""",
    ),
    CredPattern(
        "Password in YAML / ENV",
        ["password: ext:yml", "PASSWORD= ext:env", "_PASS=", "_PASSWORD="],
        Severity.HIGH,
        min_entropy=2.0,
        secret_regex=r"""(?i)(?:password|_PASS(?:WORD)?)["']?\s*[:=]\s*["']?([^\s"',;}{]{3,})""",
    ),
    # --- CI/CD & infrastructure ---
    CredPattern(
        "Docker Hub / Registry Token",
        ["docker login password", "DOCKER_PASSWORD", "registryPassword"],
        Severity.HIGH,
        min_entropy=2.5,
        secret_regex=r"""(?i)(?:DOCKER_PASSWORD|registryPassword|password)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})""",
    ),
    CredPattern(
        "Terraform / IaC Secret",
        ["secret_key ext:tf", "access_key ext:tf", "password ext:tfvars"],
        Severity.HIGH,
        min_entropy=2.5,
        secret_regex=r"""(?i)(?:secret_key|access_key|password)["']?\s*=\s*["']?([^\s"',;}{]{8,})""",
    ),
    CredPattern(
        "LDAP Bind Password",
        ["ldap bind password", "LdapPassword", "DirectoryEntry password"],
        Severity.HIGH,
        min_entropy=2.0,
        secret_regex=r"""(?i)(?:LdapPassword|password)["']?\s*[:=]\s*["']?([^\s"',;}{]{3,})""",
    ),
    # --- Google Cloud ---
    CredPattern(
        "Google Cloud Service Account",
        ["private_key_id ext:json", "type: service_account"],
        Severity.CRITICAL,
        min_entropy=3.5,
        secret_regex=r'"private_key_id"\s*:\s*"([a-f0-9]{40})"',
    ),
    # --- MSSQL-specific ---
    CredPattern(
        "MSSQL sqlcmd Password",
        ["sqlcmd -P", "sqlcmd -S -U -P"],
        Severity.CRITICAL,
        extensions=(".ps1", ".sh", ".bat", ".cmd", ".py", ".yml", ".yaml"),
        min_entropy=2.0,
        secret_regex=r"-P\s+([^\s\"';]+)",
    ),
    CredPattern(
        "MSSQL ODBC Connection String",
        ["Driver= SQL Server Pwd=", "Driver= ODBC Driver Pwd="],
        Severity.HIGH,
        _ALL_EXT,
        min_entropy=2.0,
        secret_regex=r"(?i)(?:Pwd|Password)\s*=\s*([^;\"'\s,]{3,})",
    ),
    CredPattern(
        "MSSQL Trusted_Connection=false Password",
        ["Trusted_Connection=false Password=", "Trusted_Connection=no Password="],
        Severity.HIGH,
        _ALL_EXT,
        min_entropy=2.0,
        secret_regex=r"(?i)Password\s*=\s*([^;\"'\s,]{3,})",
    ),
    CredPattern(
        "MSSQL SqlConnection in Code",
        ["SqlConnection Password=", "SqlClient Password="],
        Severity.HIGH,
        extensions=(".cs", ".vb", ".ps1", ".py", ".java"),
        min_entropy=2.0,
        secret_regex=r"(?i)Password\s*=\s*([^;\"'\s,]{3,})",
    ),
    CredPattern(
        "Service URL Credentials",
        ["url= username= password=", "url=http password="],
        Severity.HIGH,
        extensions=(".cs", ".vb", ".config", ".json", ".xml", ".yml", ".yaml", ".properties"),
        min_entropy=2.5,
        secret_regex=r"(?i)password\s*=\s*([^;\"'\s,}{]+)",
    ),
    # --- .NET hardcoded credential constructors ---
    CredPattern(
        "NetworkCredential Hardcoded",
        ["new NetworkCredential(", "NetworkCredential(@"],
        Severity.CRITICAL,
        extensions=(".cs", ".vb", ".ps1"),
        min_entropy=1.5,
        secret_regex=r"""(?i)NetworkCredential\(\s*(?:@?"[^"]*"\s*,\s*)?@?"([^"]{3,})"\s*\)""",
    ),
    CredPattern(
        "VssBasicCredential Inline Token",
        ["VssBasicCredential(", "VssCredentials("],
        Severity.CRITICAL,
        extensions=(".cs", ".vb", ".ps1"),
        min_entropy=2.0,
        secret_regex=r"""(?i)VssBasicCredential\(\s*"[^"]*"\s*,\s*"([^"]{8,})"\s*\)""",
    ),
    # --- Jenkins CI secrets in XML ---
    CredPattern(
        "Jenkins Encrypted Password",
        ["<password>", "<hudsonSecret>", "<secret>"],
        Severity.HIGH,
        extensions=(".xml",),
        min_entropy=2.5,
        secret_regex=r"<(?:password|hudsonSecret|secret)>([^<]{8,})</(?:password|hudsonSecret|secret)>",
    ),
    CredPattern(
        "Jenkins Auth / Build Token",
        ["<authToken>", "<slackToken>", "<token>"],
        Severity.HIGH,
        extensions=(".xml",),
        min_entropy=2.0,
        secret_regex=r"<(?:authToken|slackToken|token)>([^<]{4,})</(?:authToken|slackToken|token)>",
    ),
    # --- JDBC ---
    CredPattern(
        "JDBC SQL Server Connection",
        ["jdbc:sqlserver password="],
        Severity.CRITICAL,
        extensions=(".properties", ".yml", ".yaml", ".xml"),
        min_entropy=2.0,
        secret_regex=r"(?i)password=([^\s;\"'&,]+)",
    ),
    # --- Inline login / password pairs (wiki, docs) ---
    CredPattern(
        "Inline Login Credentials",
        ["login:", "account owner:", "credentials:", "username:"],
        Severity.HIGH,
        min_entropy=3.0,
        secret_regex=r"""(?i)(?:(?:login|account(?:\s*owner)?|credentials?|creds|user(?:name)?)[*_]*\s*[:=][*_]*\s*`?\S+`?|`?\b(?:sa|admin|root|administrator|postgres)\b`?)\s+/\s+`?((?=[^\s,;`]*[^a-zA-Z0-9\s,;`])[^\s,;`]{6,})""",
    ),
    # --- Hardcoded default / known passwords ---
    CredPattern(
        "Hardcoded Default Password",
        ["adminadmin", "password123", "P@ssw0rd", "changeme", "Welcome1"],
        Severity.HIGH,
        min_entropy=1.0,
        secret_regex=r"""(?i)(?:password|pwd)\s*[:=]\s*["']?(adminadmin[^\s"',;}{]*|password123|P@ssw0rd|changeme|Welcome1)""",
    ),
]
