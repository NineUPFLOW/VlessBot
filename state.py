"""SQLite-состояние: дедупликация VLESS-ключей."""
from __future__ import annotations

import hashlib
import logging
import sqlite3
import time

logger = logging.getLogger(__name__)

DB_PATH = "vless_state.db"
SEEN_TTL = 2 * 3600
PUBLISHED_TTL = 6 * 3600
SOURCE_STATS_TTL = 7 * 24 * 3600

_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        _conn.row_factory = sqlite3.Row
    return _conn


def init_db() -> None:
    conn = _get_conn()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS seen_keys (
            hash TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            check_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_seen_last ON seen_keys(last_seen);

        CREATE TABLE IF NOT EXISTS published_keys (
            hash TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            published_at INTEGER NOT NULL,
            ping_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_pub_at ON published_keys(published_at);

        CREATE TABLE IF NOT EXISTS flags (
            name TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    logger.info("DB initialized")


def _normalize(key: dict) -> dict | None:
    ip = key.get("ip")
    port = key.get("port")
    proto = "VLESS"
    if not ip or not port:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if port <= 0 or port > 65535:
        return None
    return {"ip": str(ip), "port": port, "protocol": proto}


def _hash(p: dict) -> str:
    return hashlib.sha256(
        f"{p['ip']}:{p['port']}:{p['protocol']}".encode()
    ).hexdigest()[:16]


def mark_seen(key: dict) -> None:
    p = _normalize(key)
    if not p:
        return
    h = _hash(p)
    now = int(time.time())
    _get_conn().execute(
        """INSERT INTO seen_keys (hash, ip, port, protocol, first_seen, last_seen, check_count)
           VALUES (?,?,?,?,?,?,1)
           ON CONFLICT(hash) DO UPDATE SET
               last_seen=excluded.last_seen,
               check_count=seen_keys.check_count+1""",
        (h, p["ip"], p["port"], p["protocol"], now, now),
    )


def mark_published(key: dict) -> None:
    p = _normalize(key)
    if not p:
        return
    h = _hash(p)
    now = int(time.time())
    ping = key.get("ping")
    try:
        ping = int(ping) if ping is not None else None
    except (TypeError, ValueError):
        ping = None
    _get_conn().execute(
        """INSERT INTO published_keys (hash, ip, port, protocol, published_at, ping_ms)
           VALUES (?,?,?,?,?,?)
           ON CONFLICT(hash) DO UPDATE SET
               published_at=excluded.published_at,
               ping_ms=excluded.ping_ms""",
        (h, p["ip"], p["port"], p["protocol"], now, ping),
    )


def _bulk_filter(
    keys: list[dict], table: str, time_col: str, ttl: int
) -> list[dict]:
    if not keys:
        return []
    cutoff = int(time.time()) - ttl
    hash_to_key: dict[str, dict] = {}
    ordered: list[tuple[str, dict]] = []
    for key in keys:
        p = _normalize(key)
        if not p:
            continue
        h = _hash(p)
        hash_to_key[h] = key
        ordered.append((h, key))

    hashes = list(hash_to_key.keys())
    if not hashes:
        return []

    conn = _get_conn()
    fresh: set[str] = set()
    CHUNK = 500
    for i in range(0, len(hashes), CHUNK):
        chunk = hashes[i : i + CHUNK]
        placeholders = ",".join("?" for _ in chunk)
        rows = conn.execute(
            f"SELECT hash FROM {table} WHERE hash IN ({placeholders}) AND {time_col} >= ?",
            (*chunk, cutoff),
        ).fetchall()
        for r in rows:
            fresh.add(r["hash"])

    return [key for h, key in ordered if h not in fresh]


def filter_unseen(keys: list[dict]) -> list[dict]:
    return _bulk_filter(keys, "seen_keys", "last_seen", SEEN_TTL)


def filter_unpublished(keys: list[dict]) -> list[dict]:
    return _bulk_filter(keys, "published_keys", "published_at", PUBLISHED_TTL)


def get_flag(name: str) -> str | None:
    row = _get_conn().execute(
        "SELECT value FROM flags WHERE name=?", (name,)
    ).fetchone()
    return row["value"] if row else None


def set_flag(name: str, value: str) -> None:
    _get_conn().execute(
        "INSERT INTO flags (name,value) VALUES (?,?) "
        "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        (name, str(value)),
    )


def cleanup() -> None:
    now = int(time.time())
    conn = _get_conn()
    conn.execute("DELETE FROM seen_keys WHERE last_seen < ?", (now - SEEN_TTL,))
    conn.execute(
        "DELETE FROM published_keys WHERE published_at < ?", (now - PUBLISHED_TTL,)
    )
    logger.info("DB cleanup done")
