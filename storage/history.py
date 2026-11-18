from __future__ import annotations

from pathlib import Path
from typing import Any

from .database import Database, DatabaseError


class HistoryStore:
    def __init__(self, path: Path | str) -> None:
        self.database = Database(path)

    async def initialize(self) -> None:
        await self.database.initialize()

    async def save(self, report: Any) -> None:
        payload = report.to_dict() if hasattr(report, "to_dict") else report
        if not isinstance(payload, dict):
            raise DatabaseError("report must be serializable")
        await self.database.save_report(payload)

    async def get(self, report_id: str) -> dict[str, Any] | None:
        return await self.database.get_report(report_id)

    async def list(
        self,
        *,
        limit: int = 20,
        target_type: str | None = None,
        verdict: str | None = None,
    ) -> list[dict[str, Any]]:
        return await self.database.list_reports(limit=limit, target_type=target_type, verdict=verdict)

    async def count(self) -> int:
        return await self.database.count_reports()
