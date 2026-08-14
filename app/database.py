import json
import sqlite3
from datetime import datetime, timezone

from app.config import settings


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lookups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                provider TEXT NOT NULL,
                success INTEGER NOT NULL,
                risk_level TEXT,
                summary TEXT,
                payload TEXT NOT NULL,
                error TEXT
            )
            """
        )


def save_lookup(
    *,
    indicator: str,
    indicator_type: str,
    provider: str,
    success: bool,
    risk_level: str | None,
    summary: str,
    payload: dict,
    error: str | None = None,
) -> int:
    created_at = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO lookups (
                created_at,
                indicator,
                indicator_type,
                provider,
                success,
                risk_level,
                summary,
                payload,
                error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                indicator,
                indicator_type,
                provider,
                int(success),
                risk_level,
                summary,
                json.dumps(payload, ensure_ascii=False, default=str),
                error,
            ),
        )
        return cursor.lastrowid


def list_lookups(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                created_at,
                indicator,
                indicator_type,
                provider,
                success,
                risk_level,
                summary
            FROM lookups
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [
            dict(row) | {"success": bool(row["success"])}
            for row in rows
        ]


def get_lookup(lookup_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM lookups
            WHERE id = ?
            """,
            (lookup_id,),
        ).fetchone()

        if not row:
            return None

        item = dict(row)
        item["success"] = bool(item["success"])

        try:
            item["payload"] = json.loads(item["payload"])
        except json.JSONDecodeError:
            item["payload"] = {"raw": item["payload"]}

        return item