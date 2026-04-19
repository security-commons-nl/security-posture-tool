"""SQLite schema + helper queries voor v0.1."""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DB_PATH = Path(os.environ.get("DB_PATH", "posture.sqlite"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    upn TEXT,
    display_name TEXT,
    is_privileged INTEGER NOT NULL DEFAULT 0,
    mfa_registered INTEGER NOT NULL DEFAULT 0,
    mfa_methods TEXT,
    last_signin_at TEXT,
    source TEXT NOT NULL DEFAULT 'entra',
    collected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crown_jewels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    owner TEXT,
    vlan_or_subnet TEXT,
    backup_type TEXT,
    rto TEXT,
    rpo TEXT,
    source TEXT NOT NULL DEFAULT 'csv',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checklist_state (
    checklist_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    measured_value TEXT,
    target TEXT,
    last_measured_at TEXT,
    notes TEXT
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as conn:
        conn.executescript(SCHEMA)
    print(f"Database geïnitialiseerd op {DB_PATH.resolve()}")


def upsert_account(row: dict):
    """Schrijf een account-record (UPSERT op id)."""
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO accounts (id, upn, display_name, is_privileged,
                                  mfa_registered, mfa_methods, last_signin_at,
                                  source, collected_at)
            VALUES (:id, :upn, :display_name, :is_privileged,
                    :mfa_registered, :mfa_methods, :last_signin_at,
                    :source, :collected_at)
            ON CONFLICT(id) DO UPDATE SET
                upn=excluded.upn,
                display_name=excluded.display_name,
                is_privileged=excluded.is_privileged,
                mfa_registered=excluded.mfa_registered,
                mfa_methods=excluded.mfa_methods,
                last_signin_at=excluded.last_signin_at,
                source=excluded.source,
                collected_at=excluded.collected_at
            """,
            {
                "collected_at": datetime.utcnow().isoformat(timespec="seconds"),
                **row,
            },
        )


def insert_crown_jewel(row: dict):
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO crown_jewels (name, owner, vlan_or_subnet, backup_type,
                                      rto, rpo, source, created_at)
            VALUES (:name, :owner, :vlan_or_subnet, :backup_type,
                    :rto, :rpo, :source, :created_at)
            """,
            {
                "created_at": datetime.utcnow().isoformat(timespec="seconds"),
                "source": "csv",
                **row,
            },
        )


def set_checklist_state(checklist_id: str, label: str, measured_value: str,
                       target: str, notes: str = ""):
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO checklist_state (checklist_id, label, measured_value,
                                         target, last_measured_at, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(checklist_id) DO UPDATE SET
                label=excluded.label,
                measured_value=excluded.measured_value,
                target=excluded.target,
                last_measured_at=excluded.last_measured_at,
                notes=excluded.notes
            """,
            (
                checklist_id,
                label,
                measured_value,
                target,
                datetime.utcnow().isoformat(timespec="seconds"),
                notes,
            ),
        )


def fetch_accounts(privileged_only: bool = False):
    sql = "SELECT * FROM accounts"
    if privileged_only:
        sql += " WHERE is_privileged = 1"
    sql += " ORDER BY display_name"
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql).fetchall()]


def fetch_inactive_accounts(days: int = 90):
    """Accounts zonder sign-in in de afgelopen N dagen."""
    cutoff = (datetime.utcnow().timestamp() - days * 86400)
    with connect() as conn:
        rows = conn.execute("SELECT * FROM accounts").fetchall()
    out = []
    for r in rows:
        last = r["last_signin_at"]
        if not last:
            out.append(dict(r))
            continue
        try:
            ts = datetime.fromisoformat(last.replace("Z", "")).timestamp()
            if ts < cutoff:
                out.append(dict(r))
        except ValueError:
            continue
    return out


def fetch_crown_jewels():
    with connect() as conn:
        return [dict(r)
                for r in conn.execute(
                    "SELECT * FROM crown_jewels ORDER BY name").fetchall()]


def fetch_checklist():
    with connect() as conn:
        return [dict(r)
                for r in conn.execute(
                    "SELECT * FROM checklist_state ORDER BY checklist_id"
                ).fetchall()]


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        init()
    else:
        print("Usage: python db.py init")
