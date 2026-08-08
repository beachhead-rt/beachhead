"""Sanity-check the shared engagement_env fixture used by CLI/TUI tests."""

from __future__ import annotations

from beachhead.surface import open_surface


def test_engagement_env_is_consistent(engagement_env):
    sc = open_surface(engagement_env.store_path, engagement_env.config_path)
    assert sc.scope_match is True
    s = sc.store.summary()
    assert s.runs == 3
    assert s.resources == 0
    assert s.findings == 0
    assert s.attack_paths == 0
    sc.store.close()


def test_write_config_mismatch(engagement_env, write_config, tmp_path):
    other = write_config(
        tmp_path / "other.yaml",
        subscriptions=["22222222-2222-2222-2222-222222222222"],
    )
    sc = open_surface(engagement_env.store_path, other)
    assert sc.scope_match is False  # different scope -> different hash
    sc.store.close()
