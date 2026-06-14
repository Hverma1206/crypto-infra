import json
import sqlite3
import time
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "data" / "cache.db"

CACHE_EXPIRY_SECONDS = {
    "etherscan": 24 * 60 * 60,
    "crtsh": 72 * 60 * 60,
    "whois": 72 * 60 * 60,
    "wayback": 24 * 60 * 60,
    "scamdb": 24 * 60 * 60,
    "web_mentions": 6 * 60 * 60,
    "analysis": 6 * 60 * 60,
}


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                module TEXT NOT NULL,
                input TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (module, input)
            )
            """
        )


def get(module: str, input_value: str):
    init_db()
    key = _normalize_input(input_value)
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT data, created_at FROM cache WHERE module = ? AND input = ?",
            (module, key),
        ).fetchone()

    if not row:
        return None

    data, created_at = row
    expiry = CACHE_EXPIRY_SECONDS.get(module, 24 * 60 * 60)
    if int(time.time()) - int(created_at) > expiry:
        delete(module, key)
        return None

    try:
        return json.loads(data)
    except json.JSONDecodeError:
        delete(module, key)
        return None


def set(module: str, input_value: str, data):
    init_db()
    key = _normalize_input(input_value)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO cache (module, input, data, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (module, key, json.dumps(data, default=str), int(time.time())),
        )


def delete(module: str, input_value: str):
    init_db()
    key = _normalize_input(input_value)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM cache WHERE module = ? AND input = ?",
            (module, key),
        )


def get_stats():
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        rows = conn.execute(
            "SELECT module, COUNT(*) FROM cache GROUP BY module ORDER BY module"
        ).fetchall()

    return {
        "total_entries": total,
        "by_module": {module: count for module, count in rows},
        "db_path": str(DB_PATH),
    }


def clear():
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM cache")


def _normalize_input(input_value: str) -> str:
    return str(input_value or "").strip().lower()
