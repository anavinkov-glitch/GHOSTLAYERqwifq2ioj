"""SQLite storage.

Small enough that an ORM would cost more than it saves. Connections are
per-request and closed by Flask's teardown hook.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from typing import Any

import click
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    display_name  TEXT,
    api_key       TEXT    UNIQUE NOT NULL,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token        TEXT    UNIQUE NOT NULL,
    filename     TEXT    NOT NULL,
    sha256       TEXT    NOT NULL,
    bytes        INTEGER NOT NULL,
    score        INTEGER NOT NULL,
    verdict      TEXT    NOT NULL,
    findings     INTEGER NOT NULL,
    source       TEXT    NOT NULL DEFAULT 'web',
    report       TEXT    NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_token ON scans(token);
"""


# --------------------------------------------------------------------------
# Connection handling
# --------------------------------------------------------------------------


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = current_app.config["DATABASE"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        g.db = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    with app.app_context():
        init_db()


@click.command("init-db")
def init_db_command() -> None:
    """Create the database tables."""
    init_db()
    click.echo("Database ready.")


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


def new_api_key() -> str:
    return "gl_" + secrets.token_urlsafe(32)


def create_user(email: str, password_hash: str, display_name: str | None = None) -> int:
    db = get_db()
    cur = db.execute(
        "INSERT INTO users (email, password_hash, display_name, api_key, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (email.lower().strip(), password_hash, display_name, new_api_key(), int(time.time())),
    )
    db.commit()
    return int(cur.lastrowid)


def user_by_email(email: str) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
    ).fetchone()


def user_by_id(user_id: int) -> sqlite3.Row | None:
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def user_by_api_key(key: str) -> sqlite3.Row | None:
    if not key:
        return None
    return get_db().execute("SELECT * FROM users WHERE api_key = ?", (key.strip(),)).fetchone()


def touch_user(user_id: int) -> None:
    db = get_db()
    db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", (int(time.time()), user_id))
    db.commit()


def rotate_api_key(user_id: int) -> str:
    key = new_api_key()
    db = get_db()
    db.execute("UPDATE users SET api_key = ? WHERE id = ?", (key, user_id))
    db.commit()
    return key


# --------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------


def save_scan(user_id: int | None, result: dict, source: str = "web") -> str:
    """Store a report and return its lookup token."""
    token = secrets.token_urlsafe(16)
    db = get_db()
    db.execute(
        "INSERT INTO scans (user_id, token, filename, sha256, bytes, score, verdict,"
        " findings, source, report, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            user_id,
            token,
            result.get("filename", "document.pdf"),
            result.get("sha256", ""),
            result.get("bytes", 0),
            int(result.get("score", 0)),
            result.get("verdict", {}).get("key", "clean"),
            int(result.get("counts", {}).get("total", 0)),
            source,
            json.dumps(result),
            int(time.time()),
        ),
    )
    db.commit()
    if user_id is not None:
        _trim_history(user_id)
    return token


def _trim_history(user_id: int) -> None:
    keep = current_app.config.get("RETAIN_REPORTS", 60)
    db = get_db()
    db.execute(
        "DELETE FROM scans WHERE user_id = ? AND id NOT IN ("
        " SELECT id FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)",
        (user_id, user_id, keep),
    )
    db.commit()


def scan_by_token(token: str) -> sqlite3.Row | None:
    return get_db().execute("SELECT * FROM scans WHERE token = ?", (token,)).fetchone()


def scans_for_user(user_id: int, limit: int = 50) -> list[sqlite3.Row]:
    return get_db().execute(
        "SELECT id, token, filename, score, verdict, findings, bytes, source, created_at"
        " FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()


def delete_scan(token: str, user_id: int) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM scans WHERE token = ? AND user_id = ?", (token, user_id))
    db.commit()
    return cur.rowcount > 0


def claim_guest_scans(tokens: list[str], user_id: int) -> int:
    """Attach scans run before sign-up to the new account."""
    if not tokens:
        return 0
    db = get_db()
    marks = ",".join("?" for _ in tokens)
    cur = db.execute(
        f"UPDATE scans SET user_id = ? WHERE user_id IS NULL AND token IN ({marks})",
        [user_id, *tokens],
    )
    db.commit()
    return cur.rowcount


def user_stats(user_id: int) -> dict[str, Any]:
    row = get_db().execute(
        "SELECT COUNT(*) AS total,"
        " COALESCE(SUM(CASE WHEN verdict IN ('poisoned','suspicious') THEN 1 ELSE 0 END), 0) AS flagged,"
        " COALESCE(SUM(findings), 0) AS findings,"
        " COALESCE(MAX(score), 0) AS worst"
        " FROM scans WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    return dict(row) if row else {"total": 0, "flagged": 0, "findings": 0, "worst": 0}


def platform_stats() -> dict[str, Any]:
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) AS scans,"
        " COALESCE(SUM(CASE WHEN verdict IN ('poisoned','suspicious') THEN 1 ELSE 0 END), 0) AS flagged,"
        " COALESCE(SUM(findings), 0) AS findings FROM scans"
    ).fetchone()
    users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    stats = dict(row) if row else {"scans": 0, "flagged": 0, "findings": 0}
    stats["users"] = users["n"] if users else 0
    return stats
