"""The shared CLI/TUI bootstrap: load config, open store read-only, compare scope hash."""

from __future__ import annotations

import textwrap

import pytest

from beachhead.core.config import load_config
from beachhead.core.errors import ConfigError
from beachhead.core.store.engine import open_store
from beachhead.surface import format_duration, open_surface

_CONFIG_YAML = textwrap.dedent(
    """
    engagement: "ACME-2026-Q2"
    authorization_ref: "SOW-1 / RoE"
    window:
      start: 2026-01-01T00:00:00Z
      end:   2030-01-01T00:00:00Z
    subscriptions: ["11111111-1111-1111-1111-111111111111"]
    allow_write: false
    """
)


def _write_config(tmp_path, body=_CONFIG_YAML):
    p = tmp_path / "engagement.local.yaml"
    p.write_text(body)
    return str(p)


def _make_store(tmp_path, scope_hash):
    path = str(tmp_path / "beachhead.sqlite")
    st = open_store(path)
    st.ensure_engagement(name="ACME-2026-Q2", scope_hash=scope_hash)
    st.close()
    return path


def test_open_surface_match(tmp_path):
    cfg_path = _write_config(tmp_path)
    cfg = load_config(cfg_path)
    store_path = _make_store(tmp_path, cfg.scope_hash)

    sc = open_surface(store_path, cfg_path)
    assert sc.config.engagement == "ACME-2026-Q2"
    assert sc.engagement is not None
    assert sc.scope_match is True
    sc.store.close()


def test_open_surface_mismatch(tmp_path):
    cfg_path = _write_config(tmp_path)
    store_path = _make_store(tmp_path, "A-DIFFERENT-HASH")

    sc = open_surface(store_path, cfg_path)
    assert sc.scope_match is False
    sc.store.close()


def test_open_surface_missing_config(tmp_path):
    store_path = _make_store(tmp_path, "H")
    with pytest.raises(ConfigError):
        open_surface(store_path, str(tmp_path / "nope.yaml"))


def test_open_surface_missing_store_creates_it(tmp_path):
    """When the store file doesn't exist, open_surface creates it so the TUI can render."""
    cfg_path = _write_config(tmp_path)
    store_path = str(tmp_path / "nope.sqlite")
    sc = open_surface(store_path, cfg_path)
    assert sc.engagement is not None
    assert sc.engagement.name == "ACME-2026-Q2"
    assert sc.scope_match is True
    sc.store.close()


def test_open_surface_no_engagement(tmp_path):
    """Store exists but has no engagement row -> scope_match False, engagement None."""
    cfg_path = _write_config(tmp_path)
    path = str(tmp_path / "beachhead.sqlite")
    st = open_store(path)
    st.close()

    sc = open_surface(path, cfg_path)
    assert sc.engagement is None
    assert sc.scope_match is False
    sc.store.close()


def test_format_duration():
    class R:
        started_at = "2026-01-01T00:00:00+00:00"
        finished_at = "2026-01-01T00:00:02+00:00"

    assert format_duration(R()) == "2.0s"

    class Running:
        started_at = "2026-01-01T00:00:00+00:00"
        finished_at = None

    assert format_duration(Running()) == "—"
