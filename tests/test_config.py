"""Tests for core/config: loading + validation + scope_hash + bootstrap. Never a live tenant."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from beachhead.core.config import (
    EngagementConfig,
    bootstrap_config,
    load_config,
    resolve_config_path,
)
from beachhead.core.errors import BeachheadError, ConfigError, ConfigMissingError
from beachhead.core.module import EngagementConfig as EngagementConfigProtocol


def test_config_error_is_a_beachhead_error() -> None:
    assert issubclass(ConfigError, BeachheadError)
    err = ConfigError("nope")
    assert isinstance(err, BeachheadError)
    assert str(err) == "nope"


def _cfg(**overrides: object) -> EngagementConfig:
    base = dict(
        engagement="ACME-2026-Q2",
        authorization_ref="SOW-1234",
        window_start=datetime(2026, 4, 15, tzinfo=UTC),
        window_end=datetime(2026, 4, 30, tzinfo=UTC),
        tenants=frozenset({"11111111-1111-1111-1111-111111111111"}),
        management_groups=frozenset({"mg-acme"}),
        subscriptions=frozenset({"22222222-2222-2222-2222-222222222222"}),
        resource_scopes=("/subscriptions/sub/resourceGroups/rg",),
        ado_organizations=frozenset({"acme-eng"}),
        allow_write=False,
    )
    base.update(overrides)
    return EngagementConfig(**base)  # type: ignore[arg-type]


def test_engagement_config_satisfies_module_protocol() -> None:
    cfg = _cfg()
    assert isinstance(cfg, EngagementConfigProtocol)
    assert cfg.engagement == "ACME-2026-Q2"
    assert cfg.allow_write is False


def test_scope_hash_is_stable_and_hex() -> None:
    assert _cfg().scope_hash == _cfg().scope_hash
    assert len(_cfg().scope_hash) == 64  # sha256 hex


def test_scope_hash_changes_when_boundary_changes() -> None:
    base = _cfg()
    wider = _cfg(subscriptions=frozenset({"22222222-2222-2222-2222-222222222222", "extra"}))
    assert base.scope_hash != wider.scope_hash


def test_scope_hash_ignores_cosmetic_fields() -> None:
    assert _cfg().scope_hash == _cfg(engagement="other", authorization_ref="SOW-9").scope_hash


VALID_YAML = """
engagement: "ACME-2026-Q2"
authorization_ref: "SOW-1234"
window:
  start: 2026-04-15T00:00:00Z
  end:   2026-04-30T23:59:59Z
tenants: ["11111111-1111-1111-1111-111111111111"]
management_groups: ["mg-acme"]
subscriptions: ["22222222-2222-2222-2222-222222222222"]
resource_scopes:
  - "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/in-scope-rg"
ado_organizations: ["acme-eng"]
allow_write: false
"""


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "engagement.local.yaml"
    p.write_text(text)
    return p


def test_load_config_happy_path(tmp_path: Path) -> None:
    cfg = load_config(str(_write(tmp_path, VALID_YAML)))
    assert cfg.engagement == "ACME-2026-Q2"
    assert cfg.tenants == frozenset({"11111111-1111-1111-1111-111111111111"})
    assert cfg.management_groups == frozenset({"mg-acme"})
    assert cfg.resource_scopes == (
        "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/in-scope-rg",
    )
    assert cfg.allow_write is False
    # window coerced to tz-aware UTC datetimes
    assert cfg.window_start.tzinfo is not None
    assert cfg.window_start < cfg.window_end


def test_load_config_naive_datetime_rejected(tmp_path: Path) -> None:
    text = VALID_YAML.replace("2026-04-15T00:00:00Z", "2026-04-15 00:00:00")
    with pytest.raises(ConfigError, match="naive datetime"):
        load_config(str(_write(tmp_path, text)))


def test_missing_file_raises_config_missing_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigMissingError, match="not found") as exc_info:
        load_config(str(tmp_path / "nope.yaml"))
    assert exc_info.value.config_path == str(tmp_path / "nope.yaml")
    assert isinstance(exc_info.value, ConfigError)


def test_not_a_mapping_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be a YAML mapping"):
        load_config(str(_write(tmp_path, "- just\n- a\n- list\n")))


def test_missing_engagement_raises(tmp_path: Path) -> None:
    text = VALID_YAML.replace('engagement: "ACME-2026-Q2"\n', "")
    with pytest.raises(ConfigError, match="engagement"):
        load_config(str(_write(tmp_path, text)))


def test_window_end_before_start_raises(tmp_path: Path) -> None:
    text = VALID_YAML.replace("2026-04-30T23:59:59Z", "2026-04-01T00:00:00Z")
    with pytest.raises(ConfigError, match="window.end must be after"):
        load_config(str(_write(tmp_path, text)))


def test_empty_scope_raises(tmp_path: Path) -> None:
    text = """
engagement: "x"
authorization_ref: "y"
window:
  start: 2026-04-15T00:00:00Z
  end:   2026-04-30T23:59:59Z
"""
    with pytest.raises(ConfigError, match="scope is empty"):
        load_config(str(_write(tmp_path, text)))


def test_resource_scope_must_be_subscription_path(tmp_path: Path) -> None:
    text = VALID_YAML.replace(
        '  - "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/in-scope-rg"',
        '  - "resourceGroups/in-scope-rg"',
    )
    with pytest.raises(ConfigError, match="must start with '/subscriptions/'"):
        load_config(str(_write(tmp_path, text)))


def test_discovery_uses_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _write(tmp_path, VALID_YAML)
    monkeypatch.setenv("BEACHHEAD_ENGAGEMENT", str(p))
    cfg = load_config()  # no explicit path
    assert cfg.engagement == "ACME-2026-Q2"


def test_discovery_explicit_arg_beats_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = _write(tmp_path, VALID_YAML)
    other = tmp_path / "other.yaml"
    other.write_text(VALID_YAML.replace("ACME-2026-Q2", "FROM-ENV"))
    monkeypatch.setenv("BEACHHEAD_ENGAGEMENT", str(other))
    cfg = load_config(str(explicit))
    assert cfg.engagement == "ACME-2026-Q2"


def test_discovery_default_in_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BEACHHEAD_ENGAGEMENT", raising=False)
    _write(tmp_path, VALID_YAML)  # writes engagement.local.yaml in tmp_path
    monkeypatch.chdir(tmp_path)
    cfg = load_config()
    assert cfg.engagement == "ACME-2026-Q2"


def test_non_utc_offset_normalized_to_utc(tmp_path: Path) -> None:
    text = VALID_YAML.replace("2026-04-15T00:00:00Z", "2026-04-15T10:00:00+05:30")
    cfg = load_config(str(_write(tmp_path, text)))
    assert cfg.window_start == datetime(2026, 4, 15, 4, 30, tzinfo=UTC)
    assert cfg.window_start.utcoffset() == timedelta(0)


def test_bare_date_raises(tmp_path: Path) -> None:
    text = VALID_YAML.replace("2026-04-15T00:00:00Z", "2026-04-15")
    with pytest.raises(ConfigError, match="ISO-8601 datetime"):
        load_config(str(_write(tmp_path, text)))


def test_quoted_allow_write_is_rejected(tmp_path: Path) -> None:
    text = VALID_YAML.replace("allow_write: false", 'allow_write: "false"')
    with pytest.raises(ConfigError, match="allow_write must be a boolean"):
        load_config(str(_write(tmp_path, text)))


MINIMAL_YAML = """
engagement: "ACME-2026-Q2"
ado_organizations: ["acme-eng"]
"""


def test_minimal_ado_only_config(tmp_path: Path) -> None:
    cfg = load_config(str(_write(tmp_path, MINIMAL_YAML)))
    assert cfg.engagement == "ACME-2026-Q2"
    assert cfg.ado_organizations == frozenset({"acme-eng"})
    assert cfg.authorization_ref == ""
    assert cfg.allow_write is False
    assert cfg.window_start.tzinfo is not None
    assert cfg.window_end > cfg.window_start
    assert cfg.tenants == frozenset()
    assert cfg.subscriptions == frozenset()


def test_authorization_ref_defaults_to_empty(tmp_path: Path) -> None:
    text = VALID_YAML.replace('authorization_ref: "SOW-1234"\n', "")
    cfg = load_config(str(_write(tmp_path, text)))
    assert cfg.authorization_ref == ""


def test_window_defaults_to_90_days(tmp_path: Path) -> None:
    text = """
engagement: "ACME"
ado_organizations: ["acme-eng"]
"""
    cfg = load_config(str(_write(tmp_path, text)))
    delta = cfg.window_end - cfg.window_start
    assert delta.days == 90


# ---------------------------------------------------------------------------
# ConfigMissingError
# ---------------------------------------------------------------------------


def test_config_missing_error_is_config_error_subclass() -> None:
    err = ConfigMissingError("/some/path.yaml")
    assert isinstance(err, ConfigError)
    assert isinstance(err, BeachheadError)
    assert err.config_path == "/some/path.yaml"
    assert "not found" in str(err)


# ---------------------------------------------------------------------------
# resolve_config_path
# ---------------------------------------------------------------------------


def test_resolve_config_path_explicit() -> None:
    assert resolve_config_path("/custom/path.yaml") == Path("/custom/path.yaml")


def test_resolve_config_path_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEACHHEAD_ENGAGEMENT", "/env/path.yaml")
    assert resolve_config_path() == Path("/env/path.yaml")


def test_resolve_config_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BEACHHEAD_ENGAGEMENT", raising=False)
    assert resolve_config_path() == Path("engagement.local.yaml")


# ---------------------------------------------------------------------------
# bootstrap_config
# ---------------------------------------------------------------------------


def test_bootstrap_config_programmatic(tmp_path: Path) -> None:
    out = tmp_path / "engagement.local.yaml"
    result = bootstrap_config(
        str(out),
        engagement="TEST-2026",
        ado_organizations=["acme-eng"],
        tenants=[],
        subscriptions=[],
    )
    assert result == out
    assert out.exists()
    cfg = load_config(str(out))
    assert cfg.engagement == "TEST-2026"
    assert cfg.ado_organizations == frozenset({"acme-eng"})


def test_bootstrap_config_with_all_fields(tmp_path: Path) -> None:
    out = tmp_path / "engagement.local.yaml"
    bootstrap_config(
        str(out),
        engagement="FULL-2026",
        ado_organizations=["org1", "org2"],
        tenants=["t-guid"],
        subscriptions=["s-guid"],
    )
    cfg = load_config(str(out))
    assert cfg.engagement == "FULL-2026"
    assert cfg.ado_organizations == frozenset({"org1", "org2"})
    assert cfg.tenants == frozenset({"t-guid"})
    assert cfg.subscriptions == frozenset({"s-guid"})


def test_bootstrap_config_empty_scope_raises() -> None:
    with pytest.raises(ConfigError, match="at least one scope dimension"):
        bootstrap_config(
            "/dev/null",
            engagement="X",
            ado_organizations=[],
            tenants=[],
            subscriptions=[],
        )


def test_bootstrap_config_interactive_ado_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADO-only flow."""
    out = tmp_path / "engagement.local.yaml"
    inputs = iter([
        "MY-ENGAGE",         # engagement name
        "SOW-99",            # authorization ref
        "acme-eng, other",   # ado organizations
        "",                  # window days (default 90)
        "y",                 # confirm write
    ])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))
    monkeypatch.setattr("beachhead.core.config._read_pat", lambda _prompt, **kw: "")
    result = bootstrap_config(str(out))
    assert result == out
    cfg = load_config(str(out))
    assert cfg.engagement == "MY-ENGAGE"
    assert cfg.authorization_ref == "SOW-99"
    assert cfg.ado_organizations == frozenset({"acme-eng", "other"})
    assert cfg.tenants == frozenset()
    assert cfg.allow_write is False
    # Window defaults to 90 days
    delta = cfg.window_end - cfg.window_start
    assert delta.days == 90


def test_bootstrap_config_interactive_custom_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Custom window days."""
    out = tmp_path / "engagement.local.yaml"
    inputs = iter([
        "WIN-TEST", "",             # engagement, auth
        "org1",                     # ado orgs
        "30",                       # window = 30 days
        "y",                        # confirm
    ])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))
    monkeypatch.setattr("beachhead.core.config._read_pat", lambda _prompt, **kw: "")
    bootstrap_config(str(out))
    cfg = load_config(str(out))
    assert cfg.ado_organizations == frozenset({"org1"})
    delta = cfg.window_end - cfg.window_start
    assert delta.days == 30


def test_bootstrap_config_interactive_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "engagement.local.yaml"
    inputs = iter([
        "DECLINE", "",              # engagement, auth
        "org1",                     # ado orgs
        "",                         # window days (default 90)
        "n",                        # decline write
    ])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))
    monkeypatch.setattr("beachhead.core.config._read_pat", lambda _prompt, **kw: "")
    with pytest.raises(ConfigError, match="cancelled"):
        bootstrap_config(str(out))
    assert not out.exists()


def test_bootstrap_config_interactive_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    monkeypatch.setattr("beachhead.core.config._read_pat", lambda _prompt, **kw: "")
    with pytest.raises(ConfigError, match="cancelled"):
        bootstrap_config("/dev/null")
