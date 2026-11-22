"""Deterministic seed data for the Target_API.

5 tenants (tnt_001..tnt_005), 12 users (>= 2 per tenant, one admin, one
batch_worker), 50 invoices (ids 1001-1050, 10 per tenant, contiguous per tenant).
All values are fixed so every run produces identical data. Passwords are lab-only
credentials derived from the user number; salts are derived from the user id so
hashes are reproducible too.
"""
from __future__ import annotations

import hashlib

from app.db import Database, hash_password

TENANT_IDS = [f"tnt_{i:03d}" for i in range(1, 6)]
TENANT_NAMES = ["Acme Corp", "Globex", "Initech", "Umbrella Ltd", "Stark Industries"]

# Users per tenant: tnt_001 and tnt_002 have 3, the rest 2 => 12 users.
_USERS_PER_TENANT = [3, 3, 2, 2, 2]
INVOICES_PER_TENANT = 10
FIRST_INVOICE_ID = 1001

# (tenant index, position within tenant) -> role override
_ROLE_OVERRIDES = {(0, 0): "admin", (1, 0): "batch_worker"}

_STATUSES = ["paid", "open", "overdue", "draft", "paid"]
_CURRENCIES = ["USD", "EUR", "GBP"]


def lab_password(user_number: int) -> str:
    """Deterministic lab-only password for user ``user_number`` (1-based)."""
    return f"lab-pass-{user_number:02d}"


def seed_users_spec() -> list[dict]:
    """Return the deterministic user specs (without password hashes)."""
    users: list[dict] = []
    n = 0
    for t_idx, count in enumerate(_USERS_PER_TENANT):
        for pos in range(count):
            n += 1
            users.append({
                "id": f"usr_{n:03d}",
                "username": f"user{n:02d}@{TENANT_IDS[t_idx].replace('_', '')}.lab",
                "tenant_id": TENANT_IDS[t_idx],
                "role": _ROLE_OVERRIDES.get((t_idx, pos), "user"),
                "password": lab_password(n),
            })
    return users


def seed(db: Database) -> None:
    """Populate ``db``. Idempotent: does nothing if tenants already exist."""
    if db.count("tenants") > 0:
        return

    for tid, name in zip(TENANT_IDS, TENANT_NAMES):
        db.insert_tenant(tid, name)

    for u in seed_users_spec():
        salt = hashlib.sha256(u["id"].encode()).digest()[:16]
        db.insert_user(u["id"], u["username"], u["tenant_id"], u["role"],
                       hash_password(u["password"], salt=salt))

    invoice_id = FIRST_INVOICE_ID
    for t_idx, tid in enumerate(TENANT_IDS):
        for k in range(INVOICES_PER_TENANT):
            db.insert_invoice(
                invoice_id,
                tid,
                customer=f"{TENANT_NAMES[t_idx]} Customer {k + 1}",
                amount_cents=10_000 + 1_250 * ((t_idx * INVOICES_PER_TENANT + k) % 17),
                currency=_CURRENCIES[(t_idx + k) % len(_CURRENCIES)],
                status=_STATUSES[k % len(_STATUSES)],
            )
            invoice_id += 1

    db.add_audit("2024-01-01T00:00:00.000Z", "usr_001", "tnt_001", "seed", "initial data loaded")
    db.add_audit("2024-01-01T00:00:01.000Z", "usr_001", "tnt_001", "admin_login", "lab seed event")


def create_seeded_db(path: str = ":memory:") -> Database:
    db = Database(path)
    seed(db)
    return db
