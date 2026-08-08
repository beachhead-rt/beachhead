"""Tests for core/secret_store.py — encrypted credential storage."""

from __future__ import annotations

import os

import pytest

from beachhead.core.errors import StoreError
from beachhead.core.secret_store import (
    Credential,
    SecretStore,
    open_secret_store,
    resolve_passphrase,
    secret_store_path,
)

_TEST_PASSPHRASE = "test-passphrase-for-unit-tests"


def _in_memory_store() -> SecretStore:
    """Unencrypted in-memory store for fast unit tests of SecretStore logic."""
    import sqlite3

    conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    return SecretStore(conn)


def test_store_and_list_credential() -> None:
    store = _in_memory_store()
    cred_id = store.store_credential(
        kind="ado_credential_exposure",
        reference="repo:config/settings.json",
        run_id="run-1",
        value="DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=secret123",
        resource_id="ado://org/proj/repo",
        details={
            "credential_type": "Azure Storage Connection String",
            "source_module": "harvest.ado_credential_scan",
            "org": "org",
            "project": "proj",
            "severity": "critical",
        },
    )
    assert cred_id

    creds = store.list_credentials()
    assert len(creds) == 1
    assert isinstance(creds[0], Credential)
    assert creds[0].value == "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=secret123"
    assert creds[0].kind == "ado_credential_exposure"
    assert creds[0].details["credential_type"] == "Azure Storage Connection String"
    assert creds[0].details["org"] == "org"
    assert creds[0].details["severity"] == "critical"


def test_list_with_filters() -> None:
    store = _in_memory_store()
    store.store_credential(
        kind="k1", reference="ref1", value="v1", run_id="r1",
        details={"org": "org-a", "project": "proj-x"},
    )
    store.store_credential(
        kind="k2", reference="ref2", value="v2", run_id="r1",
        details={"org": "org-b", "project": "proj-y"},
    )
    store.store_credential(
        kind="k1", reference="ref3", value="v3", run_id="r1",
        details={"org": "org-a", "project": "proj-y"},
    )

    # kind filter still works
    assert len(store.list_credentials(kind="k1")) == 2
    assert len(store.list_credentials(kind="k2")) == 1
    assert len(store.list_credentials(kind="nonexistent")) == 0

    # org/project filtering is now done in Python over all results
    all_creds = store.list_credentials()
    assert len([c for c in all_creds if c.details.get("org") == "org-a"]) == 2
    assert len([c for c in all_creds if c.details.get("project") == "proj-y"]) == 2
    org_a_proj_x = [
        c for c in all_creds
        if c.details.get("org") == "org-a" and c.details.get("project") == "proj-x"
    ]
    assert len(org_a_proj_x) == 1


def test_credential_count() -> None:
    store = _in_memory_store()
    assert store.credential_count() == 0

    store.store_credential(
        kind="k", reference="ref", value="v", run_id="r",
    )
    assert store.credential_count() == 1


def test_secret_store_path_derivation() -> None:
    assert secret_store_path("beachhead.sqlite") == "beachhead.secrets.sqlite"
    assert secret_store_path("./beachhead.sqlite") == "beachhead.secrets.sqlite"
    assert secret_store_path("/data/engagement.sqlite").endswith("engagement.secrets.sqlite")


def test_open_secret_store_creates_encrypted_file(tmp_path) -> None:
    p = tmp_path / "test.secrets.sqlite"
    store = open_secret_store(str(p), _TEST_PASSPHRASE)
    store.store_credential(
        kind="k", reference="ref", value="secret", run_id="r",
    )
    assert store.credential_count() == 1
    store.close()
    assert p.exists()

    # Verify the file is not readable as plain sqlite
    import sqlite3

    raw = sqlite3.connect(str(p))
    with pytest.raises(sqlite3.DatabaseError):
        raw.execute("SELECT * FROM credentials")
    raw.close()


def test_open_secret_store_roundtrip(tmp_path) -> None:
    p = tmp_path / "rt.secrets.sqlite"
    store = open_secret_store(str(p), _TEST_PASSPHRASE)
    store.store_credential(kind="k", reference="ref", value="s3cret", run_id="r")
    store.close()

    store2 = open_secret_store(str(p), _TEST_PASSPHRASE)
    creds = store2.list_credentials()
    assert len(creds) == 1
    assert creds[0].value == "s3cret"
    store2.close()


def test_wrong_passphrase_raises(tmp_path) -> None:
    p = tmp_path / "wrong.secrets.sqlite"
    store = open_secret_store(str(p), "correct-passphrase")
    store.store_credential(kind="k", reference="ref", value="v", run_id="r")
    store.close()

    with pytest.raises(StoreError, match="wrong passphrase"):
        open_secret_store(str(p), "wrong-passphrase")


def test_resolve_passphrase_from_env(monkeypatch) -> None:
    monkeypatch.setenv("BH_SECRETS_KEY", "from-env")
    assert resolve_passphrase() == "from-env"


def test_resolve_passphrase_prompts_when_no_env(monkeypatch) -> None:
    monkeypatch.delenv("BH_SECRETS_KEY", raising=False)
    monkeypatch.setattr("getpass.getpass", lambda prompt: "prompted-key")
    assert resolve_passphrase() == "prompted-key"


def test_resolve_passphrase_raises_on_eof(monkeypatch) -> None:
    monkeypatch.delenv("BH_SECRETS_KEY", raising=False)

    def _raise_eof(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("getpass.getpass", _raise_eof)
    with pytest.raises(StoreError, match="No passphrase"):
        resolve_passphrase()


def test_passphrase_with_special_characters(tmp_path) -> None:
    p = tmp_path / "special.secrets.sqlite"
    weird = "p@ss'word\"with\\special;chars"
    store = open_secret_store(str(p), weird)
    store.store_credential(kind="k", reference="ref", value="v", run_id="r")
    store.close()

    store2 = open_secret_store(str(p), weird)
    assert store2.credential_count() == 1
    store2.close()
