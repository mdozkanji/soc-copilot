"""
A tiny SQLite-backed key/value cache with per-entry TTL.

Why a cache at all: VirusTotal's free tier allows 4 requests/minute and
500/day; AbuseIPDB's free tier allows 1000/day. Our own alert set re-uses
the same handful of IPs and hashes across multiple alerts (case-001 alone
touches the same host and the same external IP eight times) — without a
cache we'd burn a meaningful chunk of a day's quota re-looking-up the exact
same IP for every alert in one case.

Why SQLite and not Redis: this project already knows Redis works (ZeTA uses
it), but that's a second process to run for a personal project. SQLite is a
single file, ships with Python, and is more than fast enough for this
workload. If a later week needs multi-process/networked caching, swapping
this module out is a small, contained change because everything that talks
to the cache only ever calls .get()/.set() — see docs/architecture-notes.md
(added when that need actually arises, not speculatively now).

Why a TTL at all, rather than caching forever: threat-intel scores change
over time (a newly-seen malicious IP gets more vendor detections over the
following days; an IP can also get delisted). 24 hours is a reasonable
default for a personal-project cadence — it's a parameter, not a constant,
precisely so this can be revisited once we have a sense of how stale data
actually affects triage quality.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 hours


class SqliteCache:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    cache_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        # A fresh connection per call rather than a long-lived one: this
        # project's call volume is low (bounded by the API rate limits
        # themselves), so the simplicity of "no shared connection state to
        # reason about" wins over the small overhead of reopening a local
        # SQLite file. Worth revisiting only if profiling ever says otherwise.
        return sqlite3.connect(self.db_path)

    def get(self, key: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value_json, expires_at FROM cache WHERE cache_key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        value_json, expires_at = row
        if expires_at < time.time():
            self.delete(key)
            return None
        return json.loads(value_json)

    def set(self, key: str, value: dict[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cache (cache_key, value_json, fetched_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (key, json.dumps(value), now, now + ttl_seconds),
            )

    def delete(self, key: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM cache WHERE cache_key = ?", (key,))

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM cache")
