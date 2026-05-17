"""
Data layer for ICARUS.

Manages the SQLite database backing the demo: users (with bcrypt-hashed
credentials), flights (the travel-agency demo dataset), and notes (used
by the trusted MCP server in the cross-server shadowing attack).

Functions in this module are the data access layer for the MCP servers
and the Streamlit login flow. They return plain dicts, not ORM objects,
because the layer above serializes everything to JSON anyway.

The init_db() function is destructive: it drops and recreates all tables
from seed. This is intentional — demo state should be reproducible from
a single command, not preserved across runs.
"""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import bcrypt

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "travel_agency.db"


@contextmanager
def _connect():
    """
    Context manager for SQLite connections.

    Returns rows as sqlite3.Row (dict-like access by column name) and
    enables foreign keys. Always closes the connection on exit.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS flights;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    user_id       TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    fullname      TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    credit_card   TEXT,
    email         TEXT,
    access_token  TEXT
);

CREATE TABLE flights (
    flight_no   TEXT PRIMARY KEY,
    destination TEXT NOT NULL,
    price       TEXT NOT NULL,
    airline     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'available'
);

CREATE TABLE notes (
    note_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX idx_flights_destination ON flights(destination);
CREATE INDEX idx_notes_user ON notes(user_id);
"""

# ─── Seed data ───────────────────────────────────────────────────────────────
#
# Demo logins:
#   admin_icarus / icarus_admin_2026     (admin role — Attack 2 target)
#   alice_travel / alice_demo_pass       (regular user)
#   bob_globetrot / bob_demo_pass        (regular user)

SEED_USERS = [
    {
        "user_id": "admin_icarus",
        "password": "icarus_admin_2026",
        "fullname": "Icarus Admin",
        "role": "admin",
        "credit_card": "1111-2222-3333-4444",
        "email": "admin@icarus.local",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl9pY2FydXMiLCJyb2xlIjoiYWRtaW4ifQ.fake_demo_signature_xxxxxxxxxxxxxxxxxxxxxxxx",
    },
    {
        "user_id": "alice_travel",
        "password": "alice_demo_pass",
        "fullname": "Alice Smith",
        "role": "user",
        "credit_card": "5555-6666-7777-8888",
        "email": "alice@example.com",
        "access_token": None,
    },
    {
        "user_id": "bob_globetrot",
        "password": "bob_demo_pass",
        "fullname": "Bob Roberts",
        "role": "user",
        "credit_card": "9999-8888-7777-6666",
        "email": "bob@example.com",
        "access_token": None,
    },
]

SEED_FLIGHTS = [
    ("JL34", "Tokyo", "$450", "Japan Airlines"),
    ("TG102", "Bangkok", "$300", "Thai Airways"),
    ("KE658", "Seoul", "$420", "Korean Air"),
    ("AF276", "Paris", "$750", "Air France"),
    ("BA12", "London", "$780", "British Airways"),
    ("EK215", "Dubai", "$630", "Emirates"),
    ("DL404", "New York", "$850", "Delta Air Lines"),
    ("QF12", "Sydney", "$970", "Qantas"),
    ("SQ317", "Singapore", "$380", "Singapore Airlines"),
    ("TK198", "Istanbul", "$650", "Turkish Airlines"),
    ("LH401", "Berlin", "$720", "Lufthansa"),
    ("CX255", "Hong Kong", "$400", "Cathay Pacific"),
    ("MH89", "Kuala Lumpur", "$340", "Malaysia Airlines"),
    ("VN620", "Hanoi", "$320", "Vietnam Airlines"),
    ("CI110", "Taipei", "$410", "China Airlines"),
]

# ─── Initialization ──────────────────────────────────────────────────────────


def init_db() -> None:
    """
    Drop and recreate all tables from seed data.

    Destructive — wipes any existing demo state. Designed to be idempotent:
    running it twice produces the same result as running it once.
    """
    logger.info("Initializing database at %s", DB_FILE)

    with _connect() as conn:
        conn.executescript(SCHEMA)

        # Hash passwords at seed time. Cost factor 12 ≈ 250ms per hash.
        users_rows = [
            (
                u["user_id"],
                bcrypt.hashpw(
                    u["password"].encode(), bcrypt.gensalt(rounds=12)
                ).decode(),
                u["fullname"],
                u["role"],
                u["credit_card"],
                u["email"],
                u["access_token"],
            )
            for u in SEED_USERS
        ]
        conn.executemany(
            "INSERT INTO users (user_id, password_hash, fullname, role, "
            "credit_card, email, access_token) VALUES (?, ?, ?, ?, ?, ?, ?)",
            users_rows,
        )

        # Flights have no transformation needed.
        conn.executemany(
            "INSERT INTO flights (flight_no, destination, price, airline) "
            "VALUES (?, ?, ?, ?)",
            SEED_FLIGHTS,
        )

    logger.info(
        "Database initialized: %d users, %d flights", len(SEED_USERS), len(SEED_FLIGHTS)
    )
    print(f"[+] Database initialized at: {DB_FILE}")


# ─── User operations ─────────────────────────────────────────────────────────


def verify_user(user_id: str, password: str) -> dict[str, Any] | None:
    """
    Verify credentials. Returns a small user dict on success, None on failure.

    The returned dict deliberately omits sensitive fields (password_hash,
    credit_card, access_token) — login should not pull those into memory.
    Use get_user() if a tool needs the full record.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT user_id, password_hash, fullname, role, email FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if row is None:
        return None

    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return None

    # Strip password_hash from the returned dict.
    return {
        "user_id": row["user_id"],
        "fullname": row["fullname"],
        "role": row["role"],
        "email": row["email"],
    }


def get_user(user_id: str) -> dict[str, Any] | None:
    """
    Fetch the full user record, including sensitive fields.

    SECURITY NOTE: This function intentionally returns sensitive data
    (credit_card, access_token). It is the function the vulnerable MCP
    server's `view_user_profile` tool calls. The L3 tool-arg authorization
    layer is what prevents one user from invoking this for another user.

    The data layer itself is not authorization-aware — that responsibility
    sits in the layer above, where we have session context. This is a
    deliberate separation of concerns.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT user_id, fullname, role, credit_card, email, access_token "
            "FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    return dict(row) if row else None


# ─── Flight operations ───────────────────────────────────────────────────────


def list_flights(destination_filter: str | None = None) -> list[dict[str, Any]]:
    """List flights, optionally filtered by destination (substring match)."""
    with _connect() as conn:
        if destination_filter:
            rows = conn.execute(
                "SELECT * FROM flights WHERE destination LIKE ? ORDER BY destination",
                (f"%{destination_filter}%",),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM flights ORDER BY destination").fetchall()

    return [dict(r) for r in rows]


def book_flight(flight_no: str, user_id: str) -> dict[str, Any]:
    """
    'Book' a flight by marking it unavailable.

    user_id is logged but not enforced here — the booking model is
    intentionally simple. The point of this function in the demo is to
    serve as the rug-pull trigger (Attack 4).

    Returns a dict describing the result.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT flight_no, destination, status FROM flights WHERE flight_no = ?",
            (flight_no,),
        ).fetchone()

        if row is None:
            return {"ok": False, "reason": "flight_not_found", "flight_no": flight_no}

        if row["status"] != "available":
            return {"ok": False, "reason": "already_booked", "flight_no": flight_no}

        conn.execute(
            "UPDATE flights SET status = 'booked' WHERE flight_no = ?",
            (flight_no,),
        )

    logger.info("Flight booked: %s by %s", flight_no, user_id)
    return {"ok": True, "flight_no": flight_no, "destination": row["destination"]}


# ─── Notes operations ────────────────────────────────────────────────────────


def add_note(user_id: str, content: str) -> int:
    """Save a note for a user. Returns the new note's ID."""
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)",
            (user_id, content),
        )
        return cursor.lastrowid


def list_notes(user_id: str) -> list[dict[str, Any]]:
    """List a user's notes, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT note_id, content, created_at FROM notes "
            "WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()

    return [dict(r) for r in rows]


# ─── CLI entrypoint ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    init_db()
