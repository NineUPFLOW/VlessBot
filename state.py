"""SQLite-состояние: дедупликация, публикации, статистика, флаги."""
from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from typing import Any, Iterable

log = logging.getLogger(__name__)

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
        CREATE TABLE IF NOT EXISTS seen_proxies (
            hash       TEXT PRIMARY KEY,
            ip         TEXT NOT NULL,
            port       INTEGER NOT NULL,
            protocol   TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL,
            check_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_seen_last ON seen_proxies(last_seen);

        CREATE TABLE IF NOT EXISTS published_proxies (
            hash         TEXT PRIMARY KEY,
            ip           TEXT NOT NULL,
            port         INTEGER NOT NULL,
            protocol     TEXT NOT NULL,
            published_at INTEGER NOT NULL,
            ping_ms      INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_pub_at ON published_proxies(published_at);

        CREATE TABLE IF NOT EXISTS source_stats (
            url                   TEXT PRIMARY KEY,
            total_fetched         INTEGER NOT NULL DEFAULT 0,
            total_working         INTEGER NOT NULL DEFAULT 0,
            last_success          INTEGER,
            last_failure          INTEGER,
            consecutive_failures  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS flags (
            name  TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    log.info("DB initialized")


def _normalize_proxy(proxy: dict) -> dict | None:
    if not proxy:
        return None
    ip = proxy.get("ip") or proxy.get("host")
    port = proxy.get("port")
    proto = (proxy.get("protocol") or "VLESS").upper()
    if not ip or not port:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if port <= 0 or port > 65535:
        return None
    return {"ip": str(ip), "port": port, "protocol": proto}


def _hash_from_normalized(p: dict) -> str:
    key = f"{p['ip']}:{p['port']}:{p['protocol']}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _parse_ping_ms(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().lower().replace("ms", "").strip()
    try:
        return int(float(s))
    except ValueError:
        return None


def mark_seen(proxy: dict) -> None:
    p = _normalize_proxy(proxy)
    if not p:
        return
    h = _hash_from_normalized(p)
    now = int(time.time())
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO seen_proxies (hash, ip, port, protocol, first_seen, last_seen, check_count)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(hash) DO UPDATE SET
            last_seen = excluded.last_seen,
            check_count = seen_proxies.check_count + 1
        """,
        (h, p["ip"], p["port"], p["protocol"], now, now),
    )


def mark_published(proxy: dict) -> None:
    p = _normalize_proxy(proxy)
    if not p:
        return
    h = _hash_from_normalized(p)
    now = int(time.time())
    ping = _parse_ping_ms(proxy.get("ping"))
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO published_proxies (hash, ip, port, protocol, published_at, ping_ms)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(hash) DO UPDATE SET
            published_at = excluded.published_at,
            ping_ms = excluded.ping_ms
        """,
        (h, p["ip"], p["port"], p["protocol"], now, ping),
    )


def _bulk_filter(
    proxies: list[dict],
    table: str,
    time_col: str,
    ttl: int,
) -> list[dict]:
    if not proxies:
        return []
    cutoff = int(time.time()) - ttl
    hash_to_proxy: dict[str, dict] = {}
    ordered: list[tuple[str, dict]] = []
    for proxy in proxies:
        p = _normalize_proxy(proxy)
        if not p:
            continue
        h = _hash_from_normalized(p)
        hash_to_proxy[h] = proxy
        ordered.append((h, proxy))

    hashes = list(hash_to_proxy.keys())
    if not hashes:
        return []

    conn = _get_conn()
    fresh: set[str] = set()
    CHUNK = 500
    for i in range(0, len(hashes), CHUNK):
        chunk = hashes[i : i + CHUNK]
        placeholders = ",".join("?" for _ in chunk)
        sql = (
            f"SELECT hash FROM {table} "
            f"WHERE hash IN ({placeholders}) AND {time_col} >= ?"
        )
        rows = conn.execute(sql, (*chunk, cutoff)).fetchall()
        for r in rows:
            fresh.add(r["hash"])

    return [proxy for h, proxy in ordered if h not in fresh]


def filter_unseen(proxies: list[dict]) -> list[dict]:
    return _bulk_filter(proxies, "seen_proxies", "last_seen", SEEN_TTL)


def filter_unpublished(proxies: list[dict]) -> list[dict]:
    return _bulk_filter(proxies, "published_proxies", "published_at", PUBLISHED_TTL)


def get_flag(name: str) -> str | None:
    conn = _get_conn()
    row = conn.execute("SELECT value FROM flags WHERE name = ?", (name,)).fetchone()
    return row["value"] if row else None


def set_flag(name: str, value: str) -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO flags (name, value) VALUES (?, ?)
        ON CONFLICT(name) DO UPDATE SET value = excluded.value
        """,
        (name, str(value)),
    )


def update_source_stats(url: str, fetched: int, working: int, success: bool) -> None:
    conn = _get_conn()
    now = int(time.time())
    row = conn.execute("SELECT * FROM source_stats WHERE url = ?", (url,)).fetchone()
    if row is None:
        conn.execute(
            """
            INSERT INTO source_stats (url, total_fetched, total_working,
                last_success, last_failure, consecutive_failures)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                fetched,
                working,
                now if success else None,
                None if success else now,
                0 if success else 1,
            ),
        )
        return

    consec = 0 if success else (row["consecutive_failures"] + 1)
    conn.execute(
        """
        UPDATE source_stats SET
            total_fetched = total_fetched + ?,
            total_working = total_working + ?,
            last_success = CASE WHEN ? THEN ? ELSE last_success END,
            last_failure = CASE WHEN ? THEN ? ELSE last_failure END,
            consecutive_failures = ?
        WHERE url = ?
        """,
        (
            fetched,
            working,
            1 if success else 0,
            now,
            1 if not success else 0,
            now,
            consec,
            url,
        ),
    )


def cleanup() -> None:
    now = int(time.time())
    conn = _get_conn()
    conn.execute("DELETE FROM seen_proxies WHERE last_seen < ?", (now - SEEN_TTL,))
    conn.execute(
        "DELETE FROM published_proxies WHERE published_at < ?", (now - PUBLISHED_TTL,)
    )
    conn.execute(
        "DELETE FROM source_stats WHERE COALESCE(last_success, 0) < ?",
        (now - SOURCE_STATS_TTL,),
    )
    log.info("DB cleanup done")
