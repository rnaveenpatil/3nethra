from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_reports_completed_at ON reports(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target);
CREATE INDEX IF NOT EXISTS idx_reports_verdict ON reports(verdict);
"""


class DatabaseError(RuntimeError):
    pass


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _initialize_sync(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with sqlite3.connect(str(self.path), timeout=10) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=NORMAL")
                connection.executescript(SCHEMA)
                connection.commit()
            self.path.chmod(0o600)
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("history database could not be initialized") from exc

    async def save_report(self, report: dict[str, Any]) -> None:
        payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str)
        async with self._lock:
            await asyncio.to_thread(self._save_sync, report, payload)

    def _save_sync(self, report: dict[str, Any], payload: str) -> None:
        try:
            with sqlite3.connect(str(self.path), timeout=10) as connection:
                connection.execute(
                    """
                    INSERT INTO reports (
                        report_id, target, target_type, status, verdict, risk_score,
                        confidence, started_at, completed_at, report_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(report_id) DO UPDATE SET
                        target=excluded.target,
                        target_type=excluded.target_type,
                        status=excluded.status,
                        verdict=excluded.verdict,
                        risk_score=excluded.risk_score,
                        confidence=excluded.confidence,
                        started_at=excluded.started_at,
                        completed_at=excluded.completed_at,
                        report_json=excluded.report_json
                    """,
                    (
                        str(report.get("report_id", "")),
                        str(report.get("target", ""))[:4096],
                        str(report.get("target_type", ""))[:64],
                        str(report.get("status", ""))[:64],
                        str(report.get("verdict", ""))[:32],
                        int(report.get("risk_score", 0)),
                        float(report.get("confidence", 0.0)),
                        str(report.get("started_at", "")),
                        str(report.get("completed_at", "")),
                        payload,
                    ),
                )
                connection.commit()
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise DatabaseError("report could not be stored") from exc

    async def get_report(self, report_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._get_sync, report_id)

    def _get_sync(self, report_id: str) -> dict[str, Any] | None:
        try:
            with sqlite3.connect(str(self.path), timeout=10) as connection:
                row = connection.execute(
                    "SELECT report_json FROM reports WHERE report_id = ?",
                    (report_id,),
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("report could not be loaded") from exc
        if row is None:
            return None
        try:
            value = json.loads(row[0])
        except (ValueError, TypeError) as exc:
            raise DatabaseError("stored report is malformed") from exc
        return value if isinstance(value, dict) else None

    async def list_reports(
        self,
        *,
        limit: int = 20,
        target_type: str | None = None,
        verdict: str | None = None,
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_sync, limit, target_type, verdict)

    def _list_sync(self, limit: int, target_type: str | None, verdict: str | None) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        clauses: list[str] = []
        values: list[Any] = []
        if target_type:
            clauses.append("target_type = ?")
            values.append(target_type)
        if verdict:
            clauses.append("verdict = ?")
            values.append(verdict)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT report_id, target, target_type, status, verdict, risk_score, confidence, started_at, completed_at "
            f"FROM reports {where} ORDER BY completed_at DESC LIMIT ?"
        )
        values.append(safe_limit)
        try:
            with sqlite3.connect(str(self.path), timeout=10) as connection:
                rows = connection.execute(query, values).fetchall()
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("history could not be read") from exc
        return [
            {
                "report_id": row[0],
                "target": row[1],
                "target_type": row[2],
                "status": row[3],
                "verdict": row[4],
                "risk_score": row[5],
                "confidence": row[6],
                "started_at": row[7],
                "completed_at": row[8],
            }
            for row in rows
        ]

    async def count_reports(self) -> int:
        return await asyncio.to_thread(self._count_sync)

    def _count_sync(self) -> int:
        try:
            with sqlite3.connect(str(self.path), timeout=10) as connection:
                row = connection.execute("SELECT COUNT(*) FROM reports").fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("history could not be counted") from exc
        return int(row[0]) if row else 0
