"""SQLite store for the Target_API: tenants, users, invoices, audit log.

Passwords are stored as scrypt hashes. The module is deliberately small and
synchronous; FastAPI routes call it directly (lookups are sub-millisecond).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
from typing import Any, Iterable, Optional

DEFAULT_DB_PATH = os.environ.get("LAB_DB_PATH", ":memory:")

# scrypt parameters: modest cost so seeding 12 users stays fast.
_SCRYPT_N = 2**12
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    role          TEXT NOT NULL,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
    id          INTEGER PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    customer    TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency    TEXT NOT NULL,
    status      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    tenant_id TEXT,
    action    TEXT NOT NULL,
    detail    TEXT
);
"""


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Return ``scrypt$<salt hex>$<hash hex>``. A random salt is used if none given."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of ``password`` against a stored scrypt hash."""
    try:
        scheme, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


class Database:
    """Thin thread-safe wrapper around a single SQLite connection."""

    def __init__(self, path: str = DEFAULT_DB_PATH) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)).fetchall())

    def _execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        with self._lock:
            self._conn.execute(sql, tuple(params))
            self._conn.commit()

    # -- writes ----------------------------------------------------------
    def insert_tenant(self, tenant_id: str, name: str) -> None:
        self._execute("INSERT INTO tenants (id, name) VALUES (?, ?)", (tenant_id, name))

    def insert_user(self, user_id: str, username: str, tenant_id: str,
                    role: str, password_hash: str) -> None:
        self._execute(
            "INSERT INTO users (id, username, tenant_id, role, password_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, username, tenant_id, role, password_hash),
        )

    def insert_invoice(self, invoice_id: int, tenant_id: str, customer: str,
                       amount_cents: int, currency: str, status: str) -> None:
        self._execute(
            "INSERT INTO invoices (id, tenant_id, customer, amount_cents, currency, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (invoice_id, tenant_id, customer, amount_cents, currency, status),
        )

    def add_audit(self, ts: str, actor: str, tenant_id: Optional[str],
                  action: str, detail: Optional[str] = None) -> None:
        self._execute(
            "INSERT INTO audit_log (ts, actor, tenant_id, action, detail) VALUES (?, ?, ?, ?, ?)",
            (ts, actor, tenant_id, action, detail),
        )

    # -- reads -----------------------------------------------------------
    def get_user_by_username(self, username: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM users WHERE username = ?", (username,))
        return dict(rows[0]) if rows else None

    def get_user(self, user_id: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM users WHERE id = ?", (user_id,))
        return dict(rows[0]) if rows else None

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """Return the user row on valid credentials, else None.

        Runs a dummy hash for unknown users so timing does not reveal existence.
        """
        user = self.get_user_by_username(username)
        if user is None:
            verify_password(password, hash_password("dummy", salt=b"\0" * 16))
            return None
        return user if verify_password(password, user["password_hash"]) else None

    def get_invoice(self, invoice_id: int) -> Optional[dict]:
        rows = self._query("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
        return dict(rows[0]) if rows else None

    def list_tenants(self) -> list[dict]:
        return [dict(r) for r in self._query("SELECT * FROM tenants ORDER BY id")]

    def list_users(self) -> list[dict]:
        return [dict(r) for r in self._query("SELECT * FROM users ORDER BY id")]

    def list_invoices(self, tenant_id: Optional[str] = None) -> list[dict]:
        if tenant_id is None:
            rows = self._query("SELECT * FROM invoices ORDER BY id")
        else:
            rows = self._query("SELECT * FROM invoices WHERE tenant_id = ? ORDER BY id", (tenant_id,))
        return [dict(r) for r in rows]

    def recent_audit(self, limit: int = 50) -> list[dict]:
        rows = self._query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def count(self, table: str) -> int:
        if table not in {"tenants", "users", "invoices", "audit_log"}:
            raise ValueError(f"unknown table: {table}")
        return int(self._query(f"SELECT COUNT(*) AS c FROM {table}")[0]["c"])
