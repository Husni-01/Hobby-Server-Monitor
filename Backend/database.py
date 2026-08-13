"""
database.py — Schema initialization for LXD Monitor.

SQLite stores relational state: users, containers, permissions, audit log.
TinyFlux stores time-series metrics (one CSV file, bounded by retention policy).

Run this module directly to initialize an empty database:
    python database.py
"""

import sqlite3
import os
from tinyflux import TinyFlux

# ── Path configuration ────────────────────────────────────────────────────────
# Both the API server and the background collector import from here,
# so the paths must be absolute and consistent.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_BASE_DIR, "hobby_monitor.db")
TSDB_PATH = os.path.join(_BASE_DIR, "metrics.csv")

# ── TinyFlux shared instance ──────────────────────────────────────────────────
_tsdb = None

def get_tsdb() -> TinyFlux:
    """Returns a shared TinyFlux instance (lazy initialisation)."""
    global _tsdb
    if _tsdb is None:
        _tsdb = TinyFlux(TSDB_PATH)
    return _tsdb


# ── SQLite helpers ────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    """
    Returns a new SQLite connection with row_factory set for dict-like access.
    Callers are responsible for closing it (use as context manager where possible).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better read/write concurrency between the API server
    # and the background collector that both hit the same file.
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE,
    role            TEXT    NOT NULL DEFAULT 'user'   CHECK(role IN ('admin','user')),
    max_cpu_cores   INTEGER NOT NULL DEFAULT 2,
    max_ram_mb      INTEGER NOT NULL DEFAULT 2048,
    max_disk_gb     INTEGER NOT NULL DEFAULT 20,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Lightweight record of containers that have ever been created through this tool.
-- The authoritative live state lives in LXD; this table tracks ownership and metadata.
CREATE TABLE IF NOT EXISTS containers (
    id              TEXT    PRIMARY KEY,           -- LXD container name (unique, immutable)
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    description     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Many-to-many: which users can access which containers.
CREATE TABLE IF NOT EXISTS user_container_access (
    user_id         INTEGER NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
    container_id    TEXT    NOT NULL REFERENCES containers(id)  ON DELETE CASCADE,
    granted_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (user_id, container_id)
);

-- Immutable audit trail. Every destructive or limit-changing action is written here.
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_email     TEXT    NOT NULL,
    action          TEXT    NOT NULL,   -- e.g. 'container.delete', 'container.limits.update'
    target          TEXT    NOT NULL,   -- container name or user email
    details         TEXT,               -- JSON blob with before/after values
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""


def init_db():
    """
    Creates all tables if they do not already exist.
    Safe to call on every startup — no data is destroyed.
    """
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[DB] Schema initialised at {DB_PATH}")


# ── Audit helper ──────────────────────────────────────────────────────────────
def write_audit(actor_email: str, action: str, target: str, details: dict = None):
    """
    Appends a row to audit_log. Import and call this from any endpoint that
    performs a destructive or limit-changing operation.
    """
    import json
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (actor_email, action, target, details) VALUES (?, ?, ?, ?)",
        (actor_email, action, target, json.dumps(details) if details else None)
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database ready.")
