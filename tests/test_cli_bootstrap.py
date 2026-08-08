"""Tests for the CLI onboarding flow in ``_offer_config_creation``.

Covers: fresh-store offer (``_offer_fresh_store``).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import FakeClock, FakeIds

from beachhead.cli.common import CliOptions, _offer_fresh_store
from beachhead.core.store.engine import open_store

# ---------------------------------------------------------------------------
# _offer_fresh_store
# ---------------------------------------------------------------------------


def _make_store(path: str, engagement_name: str = "OLD-ENGAGE") -> None:
    st = open_store(path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name=engagement_name, scope_hash="h")
    st.close()


def _write_config(tmp_path: Path, engagement: str = "NEW-ENGAGE") -> str:
    import yaml

    cfg = {"engagement": engagement, "ado_organizations": ["acme-eng"]}
    p = tmp_path / "engagement.local.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return str(p)


def test_fresh_store_offers_backup_on_name_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path, "NEW-ENGAGE")
    _make_store(store_path, "OLD-ENGAGE")
    monkeypatch.setattr("builtins.input", lambda _: "y")
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)
    assert not Path(store_path).exists()
    assert (tmp_path / "beachhead.sqlite.bak").exists()


def test_fresh_store_keeps_on_decline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path, "NEW-ENGAGE")
    _make_store(store_path, "OLD-ENGAGE")
    monkeypatch.setattr("builtins.input", lambda _: "n")
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)
    assert Path(store_path).exists()
    assert not (tmp_path / "beachhead.sqlite.bak").exists()


def test_fresh_store_keeps_on_empty_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path, "NEW-ENGAGE")
    _make_store(store_path, "OLD-ENGAGE")
    monkeypatch.setattr("builtins.input", lambda _: "")
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)
    assert Path(store_path).exists()


def test_fresh_store_noop_when_same_engagement(
    tmp_path: Path,
) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path, "SAME")
    _make_store(store_path, "SAME")
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)
    assert Path(store_path).exists()
    assert not (tmp_path / "beachhead.sqlite.bak").exists()


def test_fresh_store_noop_when_no_store(tmp_path: Path) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path)
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)


def test_fresh_store_noop_when_empty_store(tmp_path: Path) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path)
    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.close()
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)
    assert Path(store_path).exists()


def test_fresh_store_handles_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_path = str(tmp_path / "beachhead.sqlite")
    config_path = _write_config(tmp_path, "NEW-ENGAGE")
    _make_store(store_path, "OLD-ENGAGE")
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError))
    opts = CliOptions(store_path=store_path, config_path=config_path)
    _offer_fresh_store(opts)
    assert Path(store_path).exists()
