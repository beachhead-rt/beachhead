"""Secure credential store — encrypted storage for discovered secrets.

A separate encrypted database (``beachhead.secrets.sqlite``) that holds the
raw credential values discovered by harvest and exploit modules. The main
store records redacted findings for attack-path analysis and reporting; this
store holds the unredacted originals for offline operator access.

The database is encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256)
via the ``cryptography`` library. The key is derived from an operator-
provided passphrase using PBKDF2-HMAC-SHA256 (600 000 iterations). The
operator provides the passphrase through the ``BH_SECRETS_KEY`` environment
variable or an interactive prompt. Without the passphrase the file is
unreadable.

File format: ``salt (16 bytes) || fernet_token(sqlite_bytes)``

The file lives alongside the main store, is gitignored by the ``*.sqlite``
pattern, and should be treated as engagement-sensitive material.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from beachhead.core.errors import StoreError

_HAS_SERIALIZE = sys.version_info >= (3, 11)

__all__ = [
    "Credential",
    "SecretStore",
    "open_secret_store",
    "resolve_passphrase",
    "secret_store_path",
]

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    resource_id     TEXT,
    reference       TEXT NOT NULL,
    redacted        INTEGER NOT NULL DEFAULT 0,
    value           TEXT NOT NULL,
    details_json    TEXT NOT NULL DEFAULT '{}',
    run_id          TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    false_positive  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_natural
    ON credentials (kind, COALESCE(resource_id, ''), reference);
"""

_KDF_ITERATIONS = 600_000
_SALT_LEN = 16


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


@dataclass(frozen=True, slots=True)
class Credential:
    """A single discovered credential — mirrors Finding plus plaintext value."""

    id: str
    kind: str
    resource_id: str | None
    reference: str
    redacted: bool
    value: str
    details: dict[str, object]
    run_id: str
    collected_at: str
    false_positive: bool = False


class SecretStore:
    """Read/write access to the encrypted credential store.

    The store operates on an in-memory SQLite database. On :meth:`close` the
    database is serialized, encrypted, and written to the on-disk file.

    The passphrase is held in memory for the store's lifetime so it can
    encrypt on close. This is an accepted risk: the process address space
    is already trusted (it holds the decrypted database), and re-prompting
    on close would break headless/batch workflows.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        path: str | None = None,
        passphrase: str | None = None,
    ) -> None:
        self._conn = conn
        self._path = path
        self._passphrase = passphrase
        self._conn.executescript(_SCHEMA)
        self._ensure_fp_column()

    def _ensure_fp_column(self) -> None:
        cols = {
            r[1]
            for r in self._conn.execute("PRAGMA table_info(credentials)").fetchall()
        }
        if "false_positive" not in cols:
            self._conn.execute(
                "ALTER TABLE credentials ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0"
            )

    def store_credential(
        self,
        *,
        kind: str,
        reference: str,
        run_id: str,
        value: str,
        resource_id: str | None = None,
        redacted: bool = False,
        details: dict[str, object] | None = None,
    ) -> str:
        cred_id = uuid.uuid4().hex
        self._conn.execute(
            "INSERT INTO credentials "
            "(id, kind, resource_id, reference, redacted,"
            " value, details_json, run_id, collected_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (kind, COALESCE(resource_id, ''), reference) "
            "DO UPDATE SET value = excluded.value,"
            " redacted = excluded.redacted,"
            " details_json = excluded.details_json,"
            " run_id = excluded.run_id,"
            " collected_at = excluded.collected_at",
            (
                cred_id,
                kind,
                resource_id,
                reference,
                int(redacted),
                value,
                json.dumps(details or {}),
                run_id,
                datetime.now(UTC).isoformat(),
            ),
        )
        return cred_id

    def dismiss_credential(self, cred_id: str) -> bool:
        self._conn.execute(
            "UPDATE credentials SET false_positive = 1 WHERE id = ?", (cred_id,)
        )
        row = self._conn.execute(
            "SELECT 1 FROM credentials WHERE id = ?", (cred_id,)
        ).fetchone()
        return row is not None

    def restore_credential(self, cred_id: str) -> bool:
        self._conn.execute(
            "UPDATE credentials SET false_positive = 0 WHERE id = ?", (cred_id,)
        )
        row = self._conn.execute(
            "SELECT 1 FROM credentials WHERE id = ?", (cred_id,)
        ).fetchone()
        return row is not None

    def list_credentials(
        self,
        *,
        kind: str | None = None,
        include_fp: bool = False,
    ) -> list[Credential]:
        cols = ("id, kind, resource_id, reference, redacted,"
                " value, details_json, run_id, collected_at, false_positive")
        clauses: list[str] = []
        params: list[object] = []
        if not include_fp:
            clauses.append("false_positive = 0")
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT {cols} FROM credentials{where}"  # noqa: S608
            " ORDER BY collected_at DESC",
            params,
        ).fetchall()
        return [_credential(r) for r in rows]

    def credential_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE false_positive = 0"
        ).fetchone()
        return row[0] if row else 0

    def flush(self) -> None:
        """Encrypt and persist the in-memory database without closing it."""
        if self._path and self._passphrase:
            _encrypt_and_write(self._conn, self._path, self._passphrase)

    def close(self) -> None:
        """Encrypt and persist the in-memory database, then close."""
        self.flush()
        self._conn.close()


def _credential(row: tuple) -> Credential:  # type: ignore[type-arg]
    return Credential(
        id=row[0],
        kind=row[1],
        resource_id=row[2],
        reference=row[3],
        redacted=bool(row[4]),
        value=row[5],
        details=json.loads(row[6]) if row[6] else {},
        run_id=row[7],
        collected_at=row[8],
        false_positive=bool(row[9]) if len(row) > 9 else False,
    )


def _encrypt_and_write(conn: Any, path: str, passphrase: str) -> None:
    """Serialize the in-memory database, encrypt, and atomically write to disk."""
    if not _HAS_SERIALIZE:
        raise StoreError(
            "Secret store encryption requires Python 3.11+ "
            f"(running {sys.version_info.major}.{sys.version_info.minor})"
        )
    salt = os.urandom(_SALT_LEN)
    key = _derive_key(passphrase, salt)
    f = Fernet(key)

    plaintext = conn.serialize()
    encrypted = f.encrypt(plaintext)

    target = Path(path)
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(salt + encrypted)
    os.replace(str(tmp), str(target))


def _decrypt_and_load(path: str, passphrase: str) -> sqlite3.Connection:
    """Read the encrypted file, decrypt, and load into an in-memory database."""
    if not _HAS_SERIALIZE:
        raise StoreError(
            "Secret store decryption requires Python 3.11+ "
            f"(running {sys.version_info.major}.{sys.version_info.minor})"
        )
    raw = Path(path).read_bytes()
    if len(raw) < _SALT_LEN + 1:
        raise StoreError(
            f"Secret store at {path} is too small to be a valid encrypted file. "
            "Re-create with: bh engage teardown --confirm"
        )

    salt = raw[:_SALT_LEN]
    encrypted = raw[_SALT_LEN:]
    key = _derive_key(passphrase, salt)
    f = Fernet(key)

    try:
        plaintext = f.decrypt(encrypted)
    except InvalidToken as exc:
        raise StoreError(
            f"Cannot decrypt secret store at {path} — wrong passphrase or "
            "corrupted/legacy unencrypted store. Re-create with: bh engage teardown --confirm"
        ) from exc

    mem_conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    mem_conn.deserialize(plaintext)
    return mem_conn


def resolve_passphrase() -> str:
    """Get the secret store passphrase from ``BH_SECRETS_KEY`` or prompt.

    Raises :class:`StoreError` if no passphrase can be resolved (env var
    unset and stdin is not a terminal).
    """
    key = os.environ.get("BH_SECRETS_KEY")
    if key:
        return key
    try:
        return getpass.getpass("Secret store passphrase: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise StoreError(
            "No passphrase provided. Set BH_SECRETS_KEY or run interactively."
        ) from exc


def secret_store_path(main_store_path: str) -> str:
    """Derive the secret store path from the main store path."""
    p = Path(main_store_path)
    return str(p.parent / (p.stem + ".secrets.sqlite"))


def open_secret_store(path: str, passphrase: str) -> SecretStore:
    """Open (or create) the encrypted credential store.

    If the file exists, it is decrypted and loaded into an in-memory SQLite
    database. If it does not exist, a fresh in-memory database is created.
    On :meth:`SecretStore.close` the database is encrypted and written back.

    Raises :class:`StoreError` if the file exists but cannot be decrypted
    (wrong passphrase or the file is an old unencrypted store).
    """
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StoreError(f"Cannot create secret store directory: {exc}") from exc

    try:
        if p.exists() and p.stat().st_size > 0:
            conn = _decrypt_and_load(path, passphrase)
        else:
            conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    except OSError as exc:
        raise StoreError(
            f"Cannot read secret store at {path}: {exc}"
        ) from exc

    return SecretStore(conn, path=path, passphrase=passphrase)
