from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from typing import Any


@dataclass
class ApprovalRequest:
    action: str
    purpose: str
    risk: str
    details: dict[str, Any]

    def render(self) -> str:
        lines = [
            f"Approval required: {self.action}",
            f"Risk: {self.risk}",
            f"Purpose: {self.purpose}",
        ]
        for key, value in list(self.details.items())[:8]:
            lines.append(f"{key}: {str(value)[:300]}")
        return "\n".join(lines)


class ApprovalBroker:
    def __init__(self, mode: str) -> None:
        if mode not in {"auto", "interactive", "deny"}:
            raise ValueError("invalid approval mode")
        self.mode = mode
        self.history: list[dict[str, Any]] = []

    async def request(
        self,
        *,
        action: str,
        purpose: str,
        risk: str = "medium",
        details: dict[str, Any] | None = None,
    ) -> bool:
        request = ApprovalRequest(
            action=action[:128],
            purpose=purpose[:512],
            risk=risk,
            details=details or {},
        )
        if self.mode == "auto":
            approved = True
        elif self.mode == "deny":
            approved = False
        else:
            approved = await self._interactive(request)
        self.history.append(
            {
                "action": request.action,
                "purpose": request.purpose,
                "risk": request.risk,
                "approved": approved,
            }
        )
        return approved

    async def _interactive(self, request: ApprovalRequest) -> bool:
        if not sys.stdin.isatty():
            return False
        print(request.render(), file=sys.stderr, flush=True)
        answer = await asyncio.to_thread(input, "Approve? [y/N] ")
        return answer.strip().lower() in {"y", "yes"}
